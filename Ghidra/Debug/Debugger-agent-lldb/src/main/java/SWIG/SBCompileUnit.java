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


public class SBCompileUnit {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBCompileUnit(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBCompileUnit obj) {
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
        lldbJNI.delete_SBCompileUnit(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBCompileUnit() {
    this(lldbJNI.new_SBCompileUnit__SWIG_0(), true);
  }

  public SBCompileUnit(SBCompileUnit rhs) {
    this(lldbJNI.new_SBCompileUnit__SWIG_1(SBCompileUnit.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBCompileUnit_IsValid(swigCPtr, this);
  }

  public SBFileSpec GetFileSpec() {
    return new SBFileSpec(lldbJNI.SBCompileUnit_GetFileSpec(swigCPtr, this), true);
  }

  public long GetNumLineEntries() {
    return lldbJNI.SBCompileUnit_GetNumLineEntries(swigCPtr, this);
  }

  public SBLineEntry GetLineEntryAtIndex(long idx) {
    return new SBLineEntry(lldbJNI.SBCompileUnit_GetLineEntryAtIndex(swigCPtr, this, idx), true);
  }

  public long FindLineEntryIndex(long start_idx, long line, SBFileSpec inline_file_spec) {
    return lldbJNI.SBCompileUnit_FindLineEntryIndex__SWIG_0(swigCPtr, this, start_idx, line, SBFileSpec.getCPtr(inline_file_spec), inline_file_spec);
  }

  public long FindLineEntryIndex(long start_idx, long line, SBFileSpec inline_file_spec, boolean exact) {
    return lldbJNI.SBCompileUnit_FindLineEntryIndex__SWIG_1(swigCPtr, this, start_idx, line, SBFileSpec.getCPtr(inline_file_spec), inline_file_spec, exact);
  }

  public SBFileSpec GetSupportFileAtIndex(long idx) {
    return new SBFileSpec(lldbJNI.SBCompileUnit_GetSupportFileAtIndex(swigCPtr, this, idx), true);
  }

  public long GetNumSupportFiles() {
    return lldbJNI.SBCompileUnit_GetNumSupportFiles(swigCPtr, this);
  }

  public long FindSupportFileIndex(long start_idx, SBFileSpec sb_file, boolean full) {
    return lldbJNI.SBCompileUnit_FindSupportFileIndex(swigCPtr, this, start_idx, SBFileSpec.getCPtr(sb_file), sb_file, full);
  }

  public SBTypeList GetTypes(long type_mask) {
    return new SBTypeList(lldbJNI.SBCompileUnit_GetTypes__SWIG_0(swigCPtr, this, type_mask), true);
  }

  public SBTypeList GetTypes() {
    return new SBTypeList(lldbJNI.SBCompileUnit_GetTypes__SWIG_1(swigCPtr, this), true);
  }

  public LanguageType GetLanguage() {
    return LanguageType.swigToEnum(lldbJNI.SBCompileUnit_GetLanguage(swigCPtr, this));
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBCompileUnit_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public String __str__() {
    return lldbJNI.SBCompileUnit___str__(swigCPtr, this);
  }

}
