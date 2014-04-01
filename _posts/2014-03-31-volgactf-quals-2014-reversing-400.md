---
layout: post
title: VolgaCTF Quals 2014 - Reversing 400
categories:
- ctf
- reversing
---

This task was quite time consuming and (at least the last time I checked, a couple of minutes before the competition ended) only solved by one other team.

The challenge binary was a tiny 32-bit Windows PE file:

> A_little_patience.exe (d8ad9fa492f117a2591c1ba80f83534c)

## Recon

Let's have a look at the `main` function:

{% highlight nasm %}
.text:00401140   push    ebp
.text:00401141   mov     ebp, esp
.text:00401143   push    Format      ; "I will give you the flag.."
.text:00401149   call    ds:printf
.text:0040114F   push    off_40301C  ; "THE FLAG IS:\n"
.text:00401155   call    ds:printf
.text:0040115B   add     esp, 8
.text:0040115E   mov     eax, 5
.text:00401163   inc     eax
.text:00401164   mov     edx, 2
.text:00401169   mul     edx
.text:0040116B   dec     eax
.text:0040116C   inc     edx
.text:0040116D   push    edx          
.text:0040116E   push    eax         
.text:0040116F   call    ds:calloc
.text:00401175   mov     esi, eax
.text:00401177   add     esp, 8
.text:0040117A   xor     edx, edx
.text:0040117C   push    edx
.text:0040117D   push    edx
.text:0040117E   push    edx
.text:0040117F   nop
.text:00401180   push    offset veh
.text:00401185   push    edx        
.text:00401186   jmp     ds:SetUnhandledExceptionFilter
{% endhighlight %}

The main function starts out pretty straight-forward: print a mocking message that the flag computation may take a while (they were not kidding), and a message in preparation for the flag output.

It continues by allocating 11 bytes of memory (initialized to zero by `calloc`). The pointer to this chunk of memory (lets call it `counter`) is stored in `esi` and as we will later see, this register remains unchanged throughout the entire execution after this.

At this point the interesting stuff starts: `edx` is set to zero and pushed onto the stack three times. We will later find out that these 12 bytes will store the computed flag.

It then calls `SetUnhandledExceptionFilter`, a pretty self explanatory Windows API: every time the program causes an exception (division by zero, access violations, ..), the provided handler `veh` will be called to give the program a chance to handle it instead of crashing immediately. I said *calls*, but really the program jumps to it but first pushes another zero onto the stack which will then be considered the return address by `SetUnhandledExceptionFilter`. Thus we know that as soon as the function is done setting up the exception handler, the program will cause its first exception by trying to execute at address `0x00000000` - how convenient!

At this point we should analyze the handler to see what's going to happen next. The handler does not contain any obfuscation so the decompiler did a pretty good job:

{% highlight cpp %}
signed int __stdcall veh(LPEXCEPTION_POINTERS ex)
{
  DWORD excode; // ecx@1
  PCONTEXT record; // eax@1
  signed int result; // eax@6

  excode = ex->ExceptionRecord->ExceptionCode;
  record = ex->ContextRecord;
  if ( excode > EXCEPTION_ILLEGAL_INSTRUCTION )
  {
    if ( excode == EXCEPTION_INT_DIVIDE_BY_ZERO )
    {
      if ( record->Esi == record->Edx )
        record->Eip += 77;
      record->Eip -= 12;
    }
    else
    {
      if ( excode == EXCEPTION_PRIV_INSTRUCTION )
      {
        if ( record->Edx == record->Esi || record->Edx == record->Ebx )
        {
          record->Eip -= 42;
          *(_DWORD *)record->Eip ^= 0xB090F2DAu;
          *(_DWORD *)(record->Eip + 4) ^= 0x25EF7A16u;
          global_var_1 = 37;
          result = EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
          record->Eip += global_var_1 - 8;
          global_var_1 = 0;
          result = EXCEPTION_CONTINUE_EXECUTION;
        }
        return result;
      }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if ( excode == EXCEPTION_ILLEGAL_INSTRUCTION )
  {
    record->Eip -= 74;
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if ( excode == EXCEPTION_BREAKPOINT )
  {
    record->Eip -= 30;
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if ( excode != EXCEPTION_SINGLE_STEP )
  {
    if ( excode == EXCEPTION_ACCESS_VIOLATION )
    {
      record->Eip = (DWORD)&loc_40119A;
      return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if ( *(_BYTE *)record->Esi )
    record->Eip += 24;
  record->Eip += 20;
  global_var_1 = 0;
  return EXCEPTION_CONTINUE_EXECUTION;
}
{% endhighlight %}

As anticipated, the handler will change the control flow of the program every time an exception is encountered. The new `eip` value will depend on the exception code (type of exception), some register values, and a global variable (from now on called `global_var_1`).

The first exception is of the type `EXCEPTION_ACCESS_VIOLATION` because we tried executing at address zero. As we can see, an exception of this type will always change the instruction pointer to address `0x0040119A` - let's have a look!

{% highlight nasm %}
.text:0040119A                 mov     ebx, 5
.text:0040119F                 mov     eax, ebx
.text:004011A1                 lea     ebx, [esi+ebx]
.text:004011A4                 mov     edx, 2
.text:004011A9                 imul    edx
.text:004011AB                 lea     edi, [esi+eax]
.text:004011AE                 pushf
.text:004011AF                 or      dword ptr [esp], 100h
.text:004011B6                 popf
.text:004011B7                 xor     ecx, ecx
{% endhighlight %}

`ebx` will point into the `counter` buffer at position 5, and `edi` will point to the last byte of the buffer. This the initialization phase, and the registers `ebx` and `edx` will also remain unchanged from this point forward. The instructions starting at `0x004011AE` have only one purpose: set `ecx` to zero and then cause an exception of the type `EXCEPTION_SINGLE_STEP` with `eip` pointing to `0x004011B9`.

The handler is once again invoked and starts by checking if the first `counter` byte is non-zero. This is not the case yet (in fact, this is the terminating condition!) so instead we increment the instruction pointer by 20, set the `global_var_1` to zero and continue execution at `eip = 0x004011B9 + 20 = 0x004011CD`.

{% highlight nasm %}
.text:004011CD                 mov     edx, edi
.text:004011CF                 xor     eax, eax
.text:004011D1                 inc     byte ptr [edx]
.text:004011D3                 setz    al
.text:004011D6                 db  0Fh
{% endhighlight %}

`edx` points to the last byte of the `counter` buffer which is then incremented, and `al` is set to 1 if the byte at `edx` is zero after the increment. Thus `al` serves as a carry flag for the increment operation on the last `counter` byte. The next instruction to be executed is invalid and causes an `EXCEPTION_ILLEGAL_INSTRUCTION`.

TODO: Finish write-up.




