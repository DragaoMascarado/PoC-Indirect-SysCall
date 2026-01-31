# Indirect Syscall Demo (x86 / WoW64)

Este repositório contém um **proof-of-concept (PoC)** demonstrando a técnica de **Indirect Syscall** no Windows **x86 (PE32 / WoW64)**, utilizando resolução manual de APIs através do **PEB (Process Environment Block)** e execução indireta de syscalls sem chamadas diretas às APIs tradicionais do Windows.

> ⚠️ Este projeto é **educacional** e voltado para estudo de **Windows Internals**, **offensive security**, **malware analysis** e **EDR research**.

---

## 📌 Visão Geral

O código demonstra como:

- Acessar o **PEB** diretamente (`fs:[0x30]`)
- Enumerar módulos carregados sem `GetModuleHandle`
- Resolver exports da `ntdll.dll` sem `GetProcAddress`
- Extrair o **System Service Number (SSN)** de funções `Nt*`
- Localizar e reutilizar um **syscall gadget** existente
- Executar uma syscall de forma **indireta**
- Alocar memória via `NtAllocateVirtualMemory` sem APIs de alto nível

Essa abordagem é comumente utilizada para **bypass de hooks em userland** implementados por AVs e EDRs.

---

## 🧠 O que é Indirect Syscall?

Um **Indirect Syscall** ocorre quando o código:

- ❌ Não chama diretamente a API (`NtAllocateVirtualMemory`)
- ❌ Não executa explicitamente a instrução `sysenter`
- ✅ Reutiliza um **gadget existente** dentro da `ntdll`
- ✅ Controla manualmente registradores como `EAX` (SSN) e `EDX`
- ✅ Entra no kernel através de código já mapeado

Diferente de **direct syscalls**, aqui o fluxo depende de um stub/gadget presente na própria `ntdll.dll`.

---

## 🧩 Principais Componentes

### 🔹 Estruturas Internas
- `PEB`
- `PEB_LDR_DATA`
- `UNICODE_STRING`
- `RTL_USER_PROCESS_PARAMETERS`

Essas estruturas são usadas para navegar internamente pelo processo sem depender da WinAPI.

---

### 🔹 Resolução Manual de Módulos
```cpp
HMODULE GetHandlePEB(LPCWSTR moduleName);
