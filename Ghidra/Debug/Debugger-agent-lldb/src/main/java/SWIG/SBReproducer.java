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


public class SBReproducer {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBReproducer(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBReproducer obj) {
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
        lldbJNI.delete_SBReproducer(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public static String Capture(String path) {
    return lldbJNI.SBReproducer_Capture(path);
  }

  public static String PassiveReplay(String path) {
    return lldbJNI.SBReproducer_PassiveReplay(path);
  }

  public static boolean SetAutoGenerate(boolean b) {
    return lldbJNI.SBReproducer_SetAutoGenerate(b);
  }

  public static void SetWorkingDirectory(String path) {
    lldbJNI.SBReproducer_SetWorkingDirectory(path);
  }

  public SBReproducer() {
    this(lldbJNI.new_SBReproducer(), true);
  }

}
