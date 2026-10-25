
function injectCEHelperLib()
  if getAddressSafe('csenter')==nil then
    local s
    if targetIsX86() then
      s=[[
alloc(cespinlock,32)
cespinlock:
]]

      if targetIs64Bit() then
        if getABI()==0 then
          s=s..[[
lock bts [rcx],0
]]
        else

          s=s..[[
lock bts [rdi],0
]]
        end
      else

        s=s..[[
mov eax,[esp+4]
lock bts [eax],0
]]
      end

      s=s..[[
jc cespinlock_wait
ret

cespinlock_wait:
pause
jmp cespinlock
]]
    else
      error("todo: implement a spinlock for arm (could halfass it and just call and api)")
    end

    s=s..[[
{$c}
    #include <celib.h>
    extern void cespinlock(int *lock);
#ifdef _WIN32
    extern int getCurrentThreadID();
#else
    extern int gettid();
    int getCurrentThreadID()
    {
      return gettid();
    }
#endif

    void csenter(cecs *cs)
    {
      if ((cs->locked) && (cs->threadid==getCurrentThreadID()))
      {
        cs->lockcount++;
        return;
      }

      cespinlock(&cs->locked);
      cs->threadid=getCurrentThreadID();
      cs->lockcount++;
    }

    void csleave(cecs *cs)
    {
      cs->lockcount--;
      if (cs->lockcount==0)
      {
        cs->threadid=0;
        cs->locked=0;
      }

    }
{$asm}
]]

    local r,r2=autoAssemble(s)
    if r then
      r2.ccodesymbols.name='CELib'
      return r
    else
      return false, r2
    end
  else
    return true
  end
end
