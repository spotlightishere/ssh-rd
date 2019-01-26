/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class Jsyringe */

#ifndef _Included_Jsyringe
#define _Included_Jsyringe
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     Jsyringe
 * Method:    download_file_from_zip
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_gui_Jsyringe_download_1file_1from_1zip
  (JNIEnv *, jclass, jstring, jstring, jstring);

/*
 * Class:     Jsyringe
 * Method:    exploit
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_gui_Jsyringe_exploit
  (JNIEnv *, jclass);

/*
 * Class:     Jsyringe
 * Method:    process_img3_file
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_gui_Jsyringe_process_1img3_1file
  (JNIEnv *, jclass, jstring, jstring, jstring, jstring, jstring);

/*
 * Class:     Jsyringe
 * Method:    add_ssh_to_ramdisk
 * Signature: (Ljava/lang/String;Ljava/lang/String;J)Z
 */
JNIEXPORT jboolean JNICALL Java_gui_Jsyringe_add_1ssh_1to_1ramdisk
  (JNIEnv *, jclass, jstring, jstring, jlong);

/*
 * Class:     Jsyringe
 * Method:    fuzzy_patch
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Z
 */
JNIEXPORT jboolean JNICALL Java_gui_Jsyringe_fuzzy_1patch
  (JNIEnv *, jclass, jstring, jstring, jstring, jint);

/*
 * Class:     Jsyringe
 * Method:    restore_bundle
 * Signature: (Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_gui_Jsyringe_restore_1bundle
  (JNIEnv *, jclass, jstring);

/*
 * Class:     Jsyringe
 * Method:    runMobileDeviceThread
 * Signature: (LMobileDevice;)V
 */
JNIEXPORT void JNICALL Java_gui_Jsyringe_runMobileDeviceThread
  (JNIEnv *, jclass, jobject);

/*
 * Class:     Jsyringe
 * Method:    startMuxThread
 * Signature: (II)Z
 */
JNIEXPORT jboolean JNICALL Java_gui_Jsyringe_startMuxThread
  (JNIEnv *, jclass, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
