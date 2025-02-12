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


public final class AccessType {
  public final static AccessType eAccessNone = new AccessType("eAccessNone");
  public final static AccessType eAccessPublic = new AccessType("eAccessPublic");
  public final static AccessType eAccessPrivate = new AccessType("eAccessPrivate");
  public final static AccessType eAccessProtected = new AccessType("eAccessProtected");
  public final static AccessType eAccessPackage = new AccessType("eAccessPackage");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static AccessType swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + AccessType.class + " with value " + swigValue);
  }

  private AccessType(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private AccessType(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private AccessType(String swigName, AccessType swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static AccessType[] swigValues = { eAccessNone, eAccessPublic, eAccessPrivate, eAccessProtected, eAccessPackage };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

