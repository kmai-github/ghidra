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


public final class ReturnStatus {
  public final static ReturnStatus eReturnStatusInvalid = new ReturnStatus("eReturnStatusInvalid");
  public final static ReturnStatus eReturnStatusSuccessFinishNoResult = new ReturnStatus("eReturnStatusSuccessFinishNoResult");
  public final static ReturnStatus eReturnStatusSuccessFinishResult = new ReturnStatus("eReturnStatusSuccessFinishResult");
  public final static ReturnStatus eReturnStatusSuccessContinuingNoResult = new ReturnStatus("eReturnStatusSuccessContinuingNoResult");
  public final static ReturnStatus eReturnStatusSuccessContinuingResult = new ReturnStatus("eReturnStatusSuccessContinuingResult");
  public final static ReturnStatus eReturnStatusStarted = new ReturnStatus("eReturnStatusStarted");
  public final static ReturnStatus eReturnStatusFailed = new ReturnStatus("eReturnStatusFailed");
  public final static ReturnStatus eReturnStatusQuit = new ReturnStatus("eReturnStatusQuit");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static ReturnStatus swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + ReturnStatus.class + " with value " + swigValue);
  }

  private ReturnStatus(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private ReturnStatus(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private ReturnStatus(String swigName, ReturnStatus swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static ReturnStatus[] swigValues = { eReturnStatusInvalid, eReturnStatusSuccessFinishNoResult, eReturnStatusSuccessFinishResult, eReturnStatusSuccessContinuingNoResult, eReturnStatusSuccessContinuingResult, eReturnStatusStarted, eReturnStatusFailed, eReturnStatusQuit };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

