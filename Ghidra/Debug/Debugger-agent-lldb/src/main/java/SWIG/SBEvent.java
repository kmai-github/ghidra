/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBEvent {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBEvent(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBEvent obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBEvent(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBEvent() {
    this(lldbJNI.new_SBEvent__SWIG_0(), true);
  }

  public SBEvent(SBEvent rhs) {
    this(lldbJNI.new_SBEvent__SWIG_1(SBEvent.getCPtr(rhs), rhs), true);
  }

  public SBEvent(long event, String cstr, long cstr_len) {
    this(lldbJNI.new_SBEvent__SWIG_2(event, cstr, cstr_len), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBEvent_IsValid(swigCPtr, this);
  }

  public String GetDataFlavor() {
    return lldbJNI.SBEvent_GetDataFlavor(swigCPtr, this);
  }

  public long GetType() {
    return lldbJNI.SBEvent_GetType(swigCPtr, this);
  }

  public SBBroadcaster GetBroadcaster() {
    return new SBBroadcaster(lldbJNI.SBEvent_GetBroadcaster(swigCPtr, this), true);
  }

  public String GetBroadcasterClass() {
    return lldbJNI.SBEvent_GetBroadcasterClass(swigCPtr, this);
  }

  public boolean BroadcasterMatchesRef(SBBroadcaster broadcaster) {
    return lldbJNI.SBEvent_BroadcasterMatchesRef(swigCPtr, this, SBBroadcaster.getCPtr(broadcaster), broadcaster);
  }

  public void Clear() {
    lldbJNI.SBEvent_Clear(swigCPtr, this);
  }

  public static String GetCStringFromEvent(SBEvent event) {
    return lldbJNI.SBEvent_GetCStringFromEvent(SBEvent.getCPtr(event), event);
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBEvent_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description);
  }

}
