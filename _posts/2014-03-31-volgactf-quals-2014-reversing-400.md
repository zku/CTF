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
.text:0040119A   mov     ebx, 5
.text:0040119F   mov     eax, ebx
.text:004011A1   lea     ebx, [esi+ebx]
.text:004011A4   mov     edx, 2
.text:004011A9   imul    edx
.text:004011AB   lea     edi, [esi+eax]
.text:004011AE   pushf
.text:004011AF   or      dword ptr [esp], 100h
.text:004011B6   popf
.text:004011B7   xor     ecx, ecx
{% endhighlight %}

`ebx` will point into the `counter` buffer at position 5, and `edi` will point to the last byte of the buffer. This the initialization phase, and the registers `ebx` and `edx` will also remain unchanged from this point forward. The instructions starting at `0x004011AE` have only one purpose: set `ecx` to zero and then cause an exception of the type `EXCEPTION_SINGLE_STEP` with `eip` pointing to `0x004011B9`.

The handler is once again invoked and starts by checking if the first `counter` byte is non-zero. This is not the case yet (in fact, this is the terminating condition!) so instead we increment the instruction pointer by 20, set the `global_var_1` to zero and continue execution at `eip = 0x004011B9 + 20 = 0x004011CD`.

{% highlight nasm %}
.text:004011CD   mov     edx, edi
.text:004011CF   xor     eax, eax
.text:004011D1   inc     byte ptr [edx]
.text:004011D3   setz    al
.text:004011D6   db  0Fh
{% endhighlight %}

`edx` points to the last byte of the `counter` buffer which is then incremented, and `al` is set to 1 if the byte at `edx` is zero after the increment. Thus `al` serves as a carry flag for the increment operation on the last `counter` byte. The next instruction to be executed is invalid and causes an `EXCEPTION_ILLEGAL_INSTRUCTION` at `0x004011D6`. Every time such an exception is encountered, the instruction pointer is decremented by 74, which brings us to `0x0040118C`.

{% highlight nasm %}
.text:0040118C   dec     edx
.text:0040118D   xor     ecx, ecx
.text:0040118F   cmp     al, 0
.text:00401191   jz      short loc_401198
.text:00401193   adc     [edx], al
.text:00401195   setz    al
.text:00401198   div     ecx
{% endhighlight %}

`edx` is decremented and now points into the second last byte of the `counter` buffer. `ecx` is set to zero and then the byte at `edx` is incremented if `al` (remember from before) is 1. Once again `al` is used as the carry flag for this increment operation. The block terminates with a division by zero causing an `EXCEPTION_INT_DIVIDE_BY_ZERO` at `0x00401198`.

If `esi` (the `counter` buffer start pointer) is equal to `edx`, the instruction pointer is incremented by 65, otherwise it is decremented by 12. At this point the register values are not equal, so we land at `eip - 12 = 0x0040118C`. **This is the same address at which we just started executing** - we have a loop that terminates as soon as `edx` is equal to `esi`!

This loop effectively emulates an 11-byte integral type stored at `esi` (the `counter`). The least significant byte is incremented by one, and the carry is propagated across the other 9 bytes! Recall the condition we encountered in the handler: as soon as the first byte at `esi` is non-zero, the control flow changes:

{% highlight python %}
counter = 0
while True:
  increment_counter_by_one()
  if counter & 0xFF00000000000000000000 != 0:
    break
  # Do something: we don't know yet.
# Do something else: also unknown.
{% endhighlight %}

After the `counter` has been incremented, the instruction pointer is incremented by 65 as described before, which brings us to `eip = 0x00401198 + 65 = 0x004011D9`.

{% highlight nasm %}
.text:004011D9   mov     edx, ebx

.text:004011DB   movzx   eax, byte ptr [edx]
.text:004011DE   add     ecx, eax
.text:004011E0   dec     edx
.text:004011E1   cmp     edx, esi
.text:004011E3   invd
{% endhighlight %}

We recall that `ebx` (and now `edx`) points into the middle of the `counter` buffer (between `esi` and `edi`). `ecx` is still zero from before and is now incremented by the byte at `edx`. `edx` is then decremented by one and `edx` is compared to `esi` to set the proper flags. What follows is a privileged instruction which will cause an `EXCEPTION_PRIV_INSTRUCTION`. If `edx` neither equal to `esi` nor `ebx` (this is currently the case), the instruction pointer is decremented by 8 which brings us to `eip = 0x004011E3 - 8 = 0x004011DB`. This is where we were just executing before, minus the initialization of the `edx` register. Another byte is taken where `edx` points to (now the second last byte of the `counter` buffer), which is then added to `ecx`. This loop continues until `edx` is either equal to `esi` or to `ebx`. We know that `ebx > esi` and `edx` was initially set to `ebx`, thus we know that the loop will finish once `edx` points to the end of the `counter` buffer. Confused yet?

{% highlight python %}
sum_in_ecx = 0
edx = ptr_to_middle_of_buffer
esi = ptr_to_start_of_buffer
while True:
  sum_in_ecx += byte_at_edx
  edx -= 1
  if edx == esi:
    break
{% endhighlight %}

Now `edx` is equal to `esi`, so the handler does this:

{% highlight cpp %}
if ( record->Edx == record->Esi || record->Edx == record->Ebx )
{
  record->Eip -= 42;
  *(_DWORD *)record->Eip ^= 0xB090F2DAu;
  *(_DWORD *)(record->Eip + 4) ^= 0x25EF7A16u;
  global_var_1 = 37;
  result = EXCEPTION_CONTINUE_EXECUTION;
}
{% endhighlight %}

Decrement the instruction pointer by 42, and then modify the first 8 bytes of code at that location. Finally, set the `global_var_1` to 37 and continue execution at `eip = 0x004011E3 - 42 = 0x004011B9`. Initially, the code at `0x004011B9` looks like this: `8B C1 59 3B C1 75 EE 33`. After the modification, the code looks like this: `51 33 C9 8B D7 0F 01 16`, which is:

{% highlight nasm %}
.text:004011B9   push ecx
.text:004011BA   xor ecx, ecx
.text:004011BC   mov edx, edi
.text:004011BE   db  0Fh
{% endhighlight %}

Well that's interesting! The accumulated value (the sum of the `counter` bytes 1, 2, 3, 4, and 5) is pushed onto the stack. After that `ecx` is once more set to zero, `edx` points to the end of the buffer, and another illegal instruction is executed. We have been there before: the byte at `edx` is added to `ecx`, `edx` is decremented until it is either equal to `esi` or `ebx`. Since `ebx > esi` and `edx` started at the end of the buffer, the accumulation loop will terminate once `edx` is equal to `ebx` - the middle of the buffer:

{% highlight python %}
sum_in_ecx = 0
edx = ptr_to_end_of_buffer
ebx = ptr_to_middle_of_buffer
while True:
  sum_in_ecx += byte_at_edx
  edx -= 1
  if edx == ebx:
    break
{% endhighlight %}

The sum of bytes 6, 7, 8, 9, and 10 is stored in `ecx` and the handler condition is met again, which means the same **xor modification** is applied to the same piece of memory, reverting it back to the original code at `0x004011B9`.

{% highlight nasm %}
.text:004011B9   mov     eax, ecx
.text:004011BB   pop     ecx
.text:004011BC   cmp     eax, ecx
.text:004011BE   jnz     short loc_4011AE
.text:004011C0   xor     eax, eax
{% endhighlight %}

The sum of bytes 6, 7, 8, 9, and 10 is moved into `eax`, and the sum of bytes 1, 2, 3, 4, and 5 is popped off the stack and moved into `ecx`. These 2 sums (lets call them `L` for left and `R` for right) are compared, and if they are equal to code continues execution at `0x004011C0`, otherwise it jumps to `0x004011AE`.

Remember that second address, `0x004011AE`? That's right, we have been there before!

{% highlight nasm %}
.text:004011AE   pushf
.text:004011AF   or      dword ptr [esp], 100h
.text:004011B6   popf
.text:004011B7   xor     ecx, ecx
{% endhighlight %}

This was right at the beginning!

{% highlight python %}
perform_initialization()
set_counter_to_zero()
while counter & 0xFF00000000000000000000 == 0:
  increment_counter_by_one()
  L = compute_sum_of_left_5_bytes()
  R = compute_sum_of_right_5_bytes()
  if L == R:
    # We don't know yet.
{% endhighlight %}

Now lets see what happens if these 2 sums are equal. Execution continues at `0x0040111C0`:

{% highlight nasm %}
.text:004011C0   xor     eax, eax
.text:004011C2   inc     dword ptr [ebp-0Ch]
.text:004011C5   adc     [ebp-8], eax
.text:004011C8   adc     [ebp-4], eax
.text:004011CB   nop
.text:004011CC   int     3
{% endhighlight %}

The unsigned integer at `[ebp-0Ch]` is incremented by 1, and the carry is propagated from `[ebp-8]` to `[ebp-4]`. Remember the three pushes at the very beginning? Exactly.

When the `counter` reaches `0x100000000000000000000`, the instruction pointer is set to `0x004011E5`.

{% highlight nasm %}
.text:004011E5   push    esi
.text:004011E6   call    ds:free
.text:004011EC   lea     eax, [ebp-0Ch]
.text:004011EF   mov     edx, 4
.text:004011F4   push    dword ptr [eax]
.text:004011F6   add     eax, edx
.text:004011F8   push    dword ptr [eax]
.text:004011FA   add     eax, edx
.text:004011FC   push    dword ptr [eax]
.text:004011FE   push    off_403020        ; "%x%x%x\n"
.text:00401204   call    ds:printf
.text:0040120A   call    ds:getchar
.text:00401210   add     esp, 20h
.text:00401213   pop     ebp
.text:00401214   retn
{% endhighlight %}

They didn't lie, the program will terminate by printing out the final value of the `counter` - our precious flag! That's it, problem solved, program understood.

{% highlight python %}
perform_initialization()
set_counter_to_zero()
flag = 0
while counter & 0xFF00000000000000000000 == 0:
  increment_counter_by_one()
  L = compute_sum_of_left_5_bytes()
  R = compute_sum_of_right_5_bytes()
  if L == R:
    flag += 1
{% endhighlight %}

Well actually.. how do I get the flag now, exactly?

## From fun to math

`0x100000000000000000000` iterations.. that can't be good - we probably need a better way of computing this. It took me quite some time to reverse engineer this binary, so after I had extracted the actual problem description, I was quite tired. My first approach was to give up and call it a day, but then I saw that my cousin was online so I explained the problem and in a couple of minutes he gave me a detailed, efficient solution to this problem.

The evolution of the counter looks like this:

```
       L                R
00 00 00 00 00 ' 00 00 00 00 00
00 00 00 00 00 ' 00 00 00 00 01
00 00 00 00 00 ' 00 00 00 00 02
00 00 00 00 00 ' 00 00 00 00 03
..
00 00 00 00 00 ' 00 00 00 00 FF
00 00 00 00 00 ' 00 00 00 01 00
00 00 00 00 00 ' 00 00 00 01 01
00 00 00 00 00 ' 00 00 00 01 02
..
FF FF FF FF FF ' FF FF FF FF FF
```

If we consider a base-256 number system and look at the digit sums of these 5-digit numbers, we know that they are in the range from `0` to `5 * 0xFF = 1275`. We can now incrementally build the lists for all digit sums that consist of 1-digit numbers, then 2-digit numbers, and so on until we are at 5-digit numbers. We then have to consider all possible permutations. Consider the digit sum 2 for example; how many 2-digit numbers have a digit sum of 2? Well, there is `0+2`, `2+0`, and `1+1`. How many 5-digit numbers have the digit sum 1?

```
1 = 00 + 00 + 00 + 00 + 01
1 = 00 + 00 + 00 + 01 + 00
1 = 00 + 00 + 01 + 00 + 00
1 = 00 + 01 + 00 + 00 + 00
1 = 01 + 00 + 00 + 00 + 00
```

That's 5! However, on the left side the digit sum 1 could also have come from these 5 possibilities, which is why we have to square them to get all possible permutations.

## Solution

The following code computes the amount in which the first 5 bytes `L` sum up to the same value as the last 5 bytes `R` of the `counter`.

{% highlight python %}
def compute_flag_slightly_faster():
  digitsumsPrev = [1] * 256
    for i in xrange(2, 5 + 1):
      numQs = 255 * i + 1
        digitsumsNow = [0] * numQs
        for q in xrange(0, numQs):
          for p in xrange(0, 256):
            if 0 <= q - p < numQs - 255:
              digitsumsNow[q] += digitsumsPrev[q - p]
              digitsumsPrev = digitsumsNow
              assert sum(digitsumsNow) == 256**i
  return sum(map(lambda x: x * x, digitsumsPrev))
	
print('The flag is: %x' % compute_flag_slightly_faster())
{% endhighlight %}

Which gives the flag **`6e300fbb83dbfe3900`** and 400 points for team sku! Hooray!
