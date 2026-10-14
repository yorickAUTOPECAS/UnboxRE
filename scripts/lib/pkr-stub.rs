// pkr-stub.rs — o stub de unpack do caso controlado de "packer SEM restore automático".
//
// Por que existe
// --------------
// O caso UPX (reports/unpack-iat-upx-case.md) tem caminho de volta: `upx -d` restaura
// o arquivo original. O caso que interessa de verdade é o contrário — um binário cujo
// ÚNICO caminho de volta é dinâmico: rodar até o OEP, dumpar a memória e reconstruir a
// IAT. Este arquivo é o stub que faz esse binário existir, sem depender de um protetor
// comercial (VMProtect/Themida DEMO geram imagens que o loader desta máquina rejeita —
// reports/root-cause-0xc000007b.md).
//
// Ele é compilado para um OBJETO COFF por:
//
//     rustc --crate-type=obj --emit=obj -C panic=abort \
//           --target x86_64-pc-windows-msvc -o pkr-stub.obj scripts/lib/pkr-stub.rs
//
// e o `make-packed-sample.mjs` copia os BYTES desta seção para dentro da seção `.pkr`
// do alvo. Não há link, não há runtime: só o assembler do LLVM que já vem no Rust.
//
// Contrato com o packer (o que o packer precisa respeitar)
// --------------------------------------------------------
//   * o blob é POSIÇÃO-INDEPENDENTE: só usa RIP-relativo e registradores. O packer pode
//     copiá-lo para qualquer RVA;
//   * `pkr_iat` fica DENTRO do blob; o packer calcula seu RVA (pkrPva + offset) e aponta
//     o import descriptor do stub para lá. Se o packer mover `pkr_iat`, tem que usar o
//     offset real — por isso o packer lê os offsets do próprio objeto COFF/símbolo;
//   * `pkr_cfg` começa com a magic ASCII "PKRCFG01"; os campos seguintes são preenchidos
//     pelo packer:
//         +8  key1     (u32) chave do XOR da seção de código do alvo
//         +12 key2     (u32) chave do XOR do plano de imports
//         +16 textRva  (u32) RVA da seção de código a descriptografar
//         +20 textSize (u32) tamanho em bytes
//         +24 oepRva   (u32) RVA do entrypoint real (para onde saltar no fim)
//         +28 planRva  (u32) RVA do plano de imports (dentro de .pkr)
//         +32 planSize (u32) tamanho do plano
//         +36 nDlls    (u32) quantas DLLs o plano tem
//         +40 protRva  (u32) RVA inicial da faixa de IAT a liberar para escrita
//         +44 protSize (u32) tamanho dessa faixa (0/RVA 0 = não libera)
//         +48 oepOrig8 (u64) os 8 bytes ORIGINAIS do entrypoint: o packer sobrescreve o
//              EP com um `jmp` de 5 bytes para o stub (o EP PRECISA continuar sendo um
//              alvo válido da GuardCFFunctionTable — com CFG ligado o loader valida o
//              EP e um EP em seção nova morre com 0xC0000409), e o stub devolve esses
//              bytes depois de descriptografar a seção.
//         +56 encSize  (u32) quantos bytes descriptografar (0 = não descriptografar; o
//              VirtualProtect continua valendo, porque o restore do EP escreve em .text)
//         +64 pkr_iattab: nDlls u32 com a RVA da IAT ORIGINAL de CADA DLL, na ordem do
//              plano. Existe porque a IAT NÃO é necessariamente contígua: o linker
//              alinha/preenche os blocos, então o stub não pode só andar de 8 em 8 —
//              ele reposiciona o cursor na RVA daquela DLL antes de cada bloco.
//   * o plano de imports é a lista, em texto: `DLL\0fn\0fn\0...\0\0` — o fim do plano é
//     uma string de DLL vazia. Tudo XOR'd com key2 (o stub descriptografa no lugar);
//   * import por ORDINAL vai no plano como `#170` (o stub monta o MAKEINTRESOURCE).
//
// O que o stub faz (nesta ordem)
// ------------------------------
//   1. PEB -> ImageBaseAddress (nada de import para descobrir a própria base);
//   2. descriptografa o plano de imports (in-place);
//   3. VirtualProtect(.text) -> RWX;
//   4. descriptografa a seção de código do alvo (in-place);
//   5. para cada DLL: LoadLibraryA; para cada função: GetProcAddress -> grava na IAT
//      ORIGINAL (na mesma ordem dos thunks originais);
//   6. salta para o OEP real.
//
// O que ele NÃO faz (de propósito): reconstruir os descritores de import do alvo. A IAT
// em memória passa a ter ponteiros resolvidos e NENHUM descritor — é exatamente a
// situação que exige Scylla (ou o `scripts/rebuild-iat.mjs`) para virar um dump
// analisável. Se o stub restaurasse os descritores, não haveria caso "duro" para provar.

#![no_std]
#![allow(unused)]

// Um handler de panic vazio é exigência do `#![no_std]`; nada aqui pode entrar em panic
// (não há runtime), e este símbolo nem é copiado para o alvo: o packer lê só a seção
// `.pkrstub`.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

core::arch::global_asm!(
    r#"
    .section .pkrstub,"drx"

    .globl  pkr_stub
pkr_stub:
    mov     r15, rsp                    // guarda a pilha original
    and     rsp, -16                    // e alinha (o loader entra com rsp%16 == 8)
    sub     rsp, 0x20                   // shadow space do Win64

    mov     rax, qword ptr gs:[0x60]    // PEB (em x64 é TEB+0x60; TEB+0x30 é o do x86)
    mov     rbx, qword ptr [rax + 0x10] // ImageBaseAddress
    lea     rbp, [rip + pkr_cfg]        // config (preenchida pelo packer)

    // ── 1. plano de imports: XOR in-place com key2
    mov     esi, dword ptr [rbp + 28]   // planRva
    add     rsi, rbx
    mov     ecx, dword ptr [rbp + 32]   // planSize
    mov     dl,  byte ptr [rbp + 12]    // key2
    test    ecx, ecx
    jz      .Lplan_done
.Lplan:
    xor     byte ptr [rsi], dl
    add     dl, 0x3d
    inc     rsi
    dec     ecx
    jnz     .Lplan
.Lplan_done:

    // ── 2. .text precisa ser gravável antes de descriptografar (size 0 = nada a fazer)
    mov     edx, dword ptr [rbp + 20]   // dwSize
    test    edx, edx
    jz      .Lprot2_done
    mov     eax, dword ptr [rbp + 16]   // textRva
    mov     rcx, rbx
    add     rcx, rax                    // lpAddress
    mov     r8d, 0x40                   // PAGE_EXECUTE_READWRITE
    lea     r9,  [rip + pkr_scratch]    // lpflOldProtect
    call    qword ptr [rip + pkr_iat + 16]
.Lprot2_done:

    // ── 2b. a IAT ORIGINAL vive em .rdata: sem liberar escrita o restore dá AV
    mov     eax, dword ptr [rbp + 40]   // protRva (0 = nada a fazer)
    test    eax, eax
    jz      .Lprot_done
    mov     rcx, rbx
    add     rcx, rax
    mov     edx, dword ptr [rbp + 44]   // protSize
    mov     r8d, 0x40                   // PAGE_EXECUTE_READWRITE
    lea     r9,  [rip + pkr_scratch]
    call    qword ptr [rip + pkr_iat + 16]
.Lprot_done:

    // ── 3. descriptografa a seção de código do alvo
    mov     esi, dword ptr [rbp + 16]   // textRva
    add     rsi, rbx
    mov     ecx, dword ptr [rbp + 56]   // encSize (0 = não descriptografar)
    mov     dl,  byte ptr [rbp + 8]     // key1
    test    ecx, ecx
    jz      .Ldec_done
.Ldec:
    xor     byte ptr [rsi], dl
    add     dl, 0x5b
    inc     rsi
    dec     ecx
    jnz     .Ldec
.Ldec_done:

    // ── 3b. devolve os bytes originais do EP (a descriptografia passou por cima do `jmp`).
    //      Campo zerado = variante de diagnóstico que NÃO devolve nada.
    mov     rcx, qword ptr [rbp + 48]   // 8 bytes originais do EP
    test    rcx, rcx
    jz      .Lep_ok
    mov     eax, dword ptr [rbp + 24]   // oepRva
    add     rax, rbx
    mov     qword ptr [rax], rcx
.Lep_ok:

    // ── 4. restaura a IAT original: LoadLibraryA + GetProcAddress
    cmp     dword ptr [rbp + 36], 0     // nDlls == 0 -> a IAT não deve ser tocada
    je      .Lready
    mov     edi, dword ptr [rbp + 28]   // cursor do plano
    add     rdi, rbx
    xor     r14d, r14d                  // índice da DLL
.Ldll:
    cmp     byte ptr [rdi], 0
    je      .Lready                     // string de DLL vazia = fim do plano
    mov     r12d, dword ptr [rbp + r14*4 + 64]  // RVA da IAT DESTA dll (tabela em +64)
    add     r12, rbx
    inc     r14d
    mov     rcx, rdi                    // lpLibFileName
    call    qword ptr [rip + pkr_iat]   // LoadLibraryA
    mov     r13, rax                    // hModule (preservado entre chamadas)
.Lskip_dll:
    inc     rdi
    cmp     byte ptr [rdi - 1], 0
    jne     .Lskip_dll
.Lfunc:
    cmp     byte ptr [rdi], 0
    je      .Lnext_dll
    cmp     byte ptr [rdi], 0x23        // '#' = import por ORDINAL
    je      .Lordinal
    mov     rcx, r13
    mov     rdx, rdi                    // lpProcName (por nome)
    call    qword ptr [rip + pkr_iat + 8]  // GetProcAddress
    jmp     .Lstore
.Lordinal:
    lea     rsi, [rdi + 1]              // pula o '#'
    xor     eax, eax
.Lod_digits:
    movzx   ecx, byte ptr [rsi]
    sub     ecx, 0x30
    cmp     ecx, 9
    ja      .Lod_done
    imul    eax, eax, 10
    add     eax, ecx
    inc     rsi
    jmp     .Lod_digits
.Lod_done:
    mov     rcx, r13
    mov     rdx, rax                    // ordinal como LPCSTR (MAKEINTRESOURCE)
    call    qword ptr [rip + pkr_iat + 8]
.Lstore:
    mov     qword ptr [r12], rax
    add     r12, 8
.Lskip_fn:
    inc     rdi
    cmp     byte ptr [rdi - 1], 0
    jne     .Lskip_fn
    jmp     .Lfunc
.Lnext_dll:
    inc     rdi
    jmp     .Ldll

    // ── 5. salta para o OEP real do alvo
.Lready:
    mov     rsp, r15                    // DEVOLVE a pilha como o loader a deixou: o
                                        // entrypoint original (CRT/start) lê argc/argv
                                        // do topo da pilha. Sem isto o alvo morre com
                                        // 0xC0000409 (é o `__fastfail` do cookie/CRT).
    mov     eax, dword ptr [rbp + 24]   // oepRva
    add     rax, rbx
    jmp     rax

    // ── dados (o packer calcula o RVA de cada um a partir desta seção)
    .align 8
pkr_iat:                                // preenchida pelo LOADER (import table do stub)
    .quad 0                             // +0  LoadLibraryA
    .quad 0                             // +8  GetProcAddress
    .quad 0                             // +16 VirtualProtect
    .quad 0                             // +24 reserva (mantém 32 bytes alinhados)
pkr_scratch:
    .quad 0

    .align 8
pkr_cfg:
    .byte 0x50,0x4b,0x52,0x43,0x46,0x47,0x30,0x31   // "PKRCFG01"
    .long 0                             // +8  key1
    .long 0                             // +12 key2
    .long 0                             // +16 textRva
    .long 0                             // +20 textSize
    .long 0                             // +24 oepRva
    .long 0                             // +28 planRva
    .long 0                             // +32 planSize
    .long 0                             // +36 nDlls
    .long 0                             // +40 protRva (faixa da IAT original)
    .long 0                             // +44 protSize
    .quad 0                             // +48 bytes originais do EP (8)
    .long 0                             // +56 encSize
    .long 0                             // +60 reservado
pkr_iattab:
    .zero 512                           // +64: nDlls RVAs de IAT (512 B = até 128 DLLs)
"#
);
