# JNI entry points are discovered by name from native code.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
