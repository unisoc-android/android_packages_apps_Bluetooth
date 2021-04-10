/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.bluetooth;

import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.PackageManager;
import android.content.pm.UserInfo;
import android.location.LocationManager;
import android.os.Binder;
import android.os.Build;
import android.os.ParcelUuid;
import android.os.Process;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @hide
 */

final public class Utils {
    public static final int CONN_SUCCESS = 0x00;
    public static final int CONN_ERR_ILLEGAL_COMMAND = 0x01;
    public static final int CONN_ERR_NO_CONNECTION = 0x02;
    public static final int CONN_ERR_HW_FAILURE = 0x03;
    public static final int CONN_ERR_PAGE_TIMEOUT = 0x04;
    public static final int CONN_ERR_AUTH_FAILURE = 0x05;
    public static final int CONN_ERR_KEY_MISSING = 0x06;
    public static final int CONN_ERR_MEMORY_FULL = 0x07;
    public static final int CONN_ERR_CONNECTION_TOUT = 0x08;
    public static final int CONN_ERR_MAX_NUM_OF_CONNECTIONS = 0x09;
    public static final int CONN_ERR_MAX_NUM_OF_SCOS = 0x0A;
    public static final int CONN_ERR_CONNECTION_EXISTS = 0x0B;
    public static final int CONN_ERR_COMMAND_DISALLOWED = 0x0C;
    public static final int CONN_ERR_HOST_REJECT_RESOURCES = 0x0D;
    public static final int CONN_ERR_HOST_REJECT_SECURITY = 0x0E;
    public static final int CONN_ERR_HOST_REJECT_DEVICE = 0x0F;
    public static final int CONN_ERR_HOST_TIMEOUT = 0x10;
    public static final int CONN_ERR_UNSUPPORTED_VALUE = 0x11;
    public static final int CONN_ERR_ILLEGAL_PARAMETER_FMT = 0x12;
    public static final int CONN_ERR_PEER_USER = 0x13;
    public static final int CONN_ERR_PEER_LOW_RESOURCES = 0x14;
    public static final int CONN_ERR_PEER_POWER_OFF = 0x15;
    public static final int CONN_ERR_CONN_CAUSE_LOCAL_HOST = 0x16;
    public static final int CONN_ERR_PAIRING_NOT_ALLOWED = 0x18;
    public static final int CONN_ERR_UNSUPPORTED_REM_FEATURE = 0x1A;
    public static final int CONN_ERR_INVALID_LMP_PARAM = 0x1E;
    public static final int CONN_ERR_UNSUPPORTED_LMP_FEATURE = 0x20;
    public static final int CONN_ERR_ROLE_CHANGE_NOT_ALLOWED = 0x21;
    public static final int CONN_ERR_LMP_RESPONSE_TIMEOUT = 0x22;
    public static final int CONN_ERR_LMP_ERR_TRANS_COLLISION = 0x23;
    public static final int CONN_ERR_LMP_PDU_NOT_ALLOWED = 0x24;
    public static final int CONN_ERR_ENCRY_MODE_NOT_ACCEPTABLE = 0x25;
    public static final int CONN_ERR_UNIT_KEY_USED = 0x26;
    public static final int CONN_ERR_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED = 0x29;
    public static final int CONN_ERR_DIFF_TRANSACTION_COLLISION = 0x2A;
    public static final int CONN_ERR_UNDEFINED_0x2B = 0x2B;
    public static final int CONN_ERR_INSUFFCIENT_SECURITY = 0x2F;
    public static final int CONN_ERR_UNDEFINED_0x33 = 0x33;
    public static final int CONN_ERR_INQ_RSP_DATA_TOO_LARGE = 0x36;
    public static final int CONN_ERR_SIMPLE_PAIRING_NOT_SUPPORTED = 0x37;
    public static final int CONN_ERR_HOST_BUSY_PAIRING = 0x38;
    public static final int CONN_ERR_CONTROLLER_BUSY = 0x3A;
    public static final int CONN_ERR_UNACCEPT_CONN_INTERVAL = 0x3B;
    public static final int CONN_ERR_CONN_TOUT_DUE_TO_MIC_FAILURE = 0x3D;
    public static final int CONN_ERR_CONN_FAILED_ESTABLISHMENT = 0x3E;
    public static final int CONN_ERR_MAC_CONNECTION_FAILED = 0x3F;
    public static final int CONN_HINT_TO_RECREATE_AMP_PHYS_LINK = 0xFF; 

    private static final String TAG = "BluetoothUtils";
    private static final int MICROS_PER_UNIT = 625;
    private static final String PTS_TEST_MODE_PROPERTY = "persist.bluetooth.pts";
    private static Boolean IS_DEBUG_BUILD = null;

    static final int BD_ADDR_LEN = 6; // bytes
    static final int BD_UUID_LEN = 16; // bytes

    public static String getAddressStringFromByte(byte[] address) {
        if (address == null || address.length != BD_ADDR_LEN) {
            return null;
        }

        return String.format("%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1], address[2],
                address[3], address[4], address[5]);
    }

    public static byte[] getByteAddress(BluetoothDevice device) {
        return getBytesFromAddress(device.getAddress());
    }

    public static byte[] getBytesFromAddress(String address) {
        int i, j = 0;
        byte[] output = new byte[BD_ADDR_LEN];

        for (i = 0; i < address.length(); i++) {
            if (address.charAt(i) != ':') {
                output[j] = (byte) Integer.parseInt(address.substring(i, i + 2), BD_UUID_LEN);
                j++;
                i++;
            }
        }

        return output;
    }

    public static int byteArrayToInt(byte[] valueBuf) {
        return byteArrayToInt(valueBuf, 0);
    }

    public static short byteArrayToShort(byte[] valueBuf) {
        ByteBuffer converter = ByteBuffer.wrap(valueBuf);
        converter.order(ByteOrder.nativeOrder());
        return converter.getShort();
    }

    public static int byteArrayToInt(byte[] valueBuf, int offset) {
        ByteBuffer converter = ByteBuffer.wrap(valueBuf);
        converter.order(ByteOrder.nativeOrder());
        return converter.getInt(offset);
    }

    public static String byteArrayToString(byte[] valueBuf) {
        StringBuilder sb = new StringBuilder();
        for (int idx = 0; idx < valueBuf.length; idx++) {
            if (idx != 0) {
                sb.append(" ");
            }
            sb.append(String.format("%02x", valueBuf[idx]));
        }
        return sb.toString();
    }

    /**
     * A parser to transfer a byte array to a UTF8 string
     *
     * @param valueBuf the byte array to transfer
     * @return the transferred UTF8 string
     */
    public static String byteArrayToUtf8String(byte[] valueBuf) {
        CharsetDecoder decoder = Charset.forName("UTF8").newDecoder();
        ByteBuffer byteBuffer = ByteBuffer.wrap(valueBuf);
        String valueStr = "";
        try {
            valueStr = decoder.decode(byteBuffer).toString();
        } catch (Exception ex) {
            Log.e(TAG, "Error when parsing byte array to UTF8 String. " + ex);
        }
        return valueStr;
    }

    public static byte[] intToByteArray(int value) {
        ByteBuffer converter = ByteBuffer.allocate(4);
        converter.order(ByteOrder.nativeOrder());
        converter.putInt(value);
        return converter.array();
    }

    public static byte[] uuidToByteArray(ParcelUuid pUuid) {
        int length = BD_UUID_LEN;
        ByteBuffer converter = ByteBuffer.allocate(length);
        converter.order(ByteOrder.BIG_ENDIAN);
        long msb, lsb;
        UUID uuid = pUuid.getUuid();
        msb = uuid.getMostSignificantBits();
        lsb = uuid.getLeastSignificantBits();
        converter.putLong(msb);
        converter.putLong(8, lsb);
        return converter.array();
    }

    public static byte[] uuidsToByteArray(ParcelUuid[] uuids) {
        int length = uuids.length * BD_UUID_LEN;
        ByteBuffer converter = ByteBuffer.allocate(length);
        converter.order(ByteOrder.BIG_ENDIAN);
        UUID uuid;
        long msb, lsb;
        for (int i = 0; i < uuids.length; i++) {
            uuid = uuids[i].getUuid();
            msb = uuid.getMostSignificantBits();
            lsb = uuid.getLeastSignificantBits();
            converter.putLong(i * BD_UUID_LEN, msb);
            converter.putLong(i * BD_UUID_LEN + 8, lsb);
        }
        return converter.array();
    }

    public static ParcelUuid[] byteArrayToUuid(byte[] val) {
        int numUuids = val.length / BD_UUID_LEN;
        ParcelUuid[] puuids = new ParcelUuid[numUuids];
        UUID uuid;
        int offset = 0;

        ByteBuffer converter = ByteBuffer.wrap(val);
        converter.order(ByteOrder.BIG_ENDIAN);

        for (int i = 0; i < numUuids; i++) {
            puuids[i] = new ParcelUuid(
                    new UUID(converter.getLong(offset), converter.getLong(offset + 8)));
            offset += BD_UUID_LEN;
        }
        return puuids;
    }

    public static String debugGetAdapterStateString(int state) {
        switch (state) {
            case BluetoothAdapter.STATE_OFF:
                return "STATE_OFF";
            case BluetoothAdapter.STATE_ON:
                return "STATE_ON";
            case BluetoothAdapter.STATE_TURNING_ON:
                return "STATE_TURNING_ON";
            case BluetoothAdapter.STATE_TURNING_OFF:
                return "STATE_TURNING_OFF";
            default:
                return "UNKNOWN";
        }
    }

    public static String ellipsize(String s) {
        // Only ellipsize release builds
        if (!Build.TYPE.equals("user")) {
            return s;
        }
        if (s == null) {
            return null;
        }
        if (s.length() < 3) {
            return s;
        }
        return s.charAt(0) + "⋯" + s.charAt(s.length() - 1);
    }

    public static void copyStream(InputStream is, OutputStream os, int bufferSize)
            throws IOException {
        if (is != null && os != null) {
            byte[] buffer = new byte[bufferSize];
            int bytesRead = 0;
            while ((bytesRead = is.read(buffer)) >= 0) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void safeCloseStream(InputStream is) {
        if (is != null) {
            try {
                is.close();
            } catch (Throwable t) {
                Log.d(TAG, "Error closing stream", t);
            }
        }
    }

    public static void safeCloseStream(OutputStream os) {
        if (os != null) {
            try {
                os.close();
            } catch (Throwable t) {
                Log.d(TAG, "Error closing stream", t);
            }
        }
    }

    static int sSystemUiUid = UserHandle.USER_NULL;
    public static void setSystemUiUid(int uid) {
        Utils.sSystemUiUid = uid;
    }

    static int sForegroundUserId = UserHandle.USER_NULL;
    public static void setForegroundUserId(int uid) {
        Utils.sForegroundUserId = uid;
    }

    public static boolean checkCaller() {
        int callingUser = UserHandle.getCallingUserId();
        int callingUid = Binder.getCallingUid();
        return (sForegroundUserId == callingUser) || (sSystemUiUid == callingUid)
                || (Process.SYSTEM_UID == callingUid);
    }

    public static boolean checkCallerAllowManagedProfiles(Context mContext) {
        if (mContext == null) {
            return checkCaller();
        }
        int callingUser = UserHandle.getCallingUserId();
        int callingUid = Binder.getCallingUid();

        // Use the Bluetooth process identity when making call to get parent user
        long ident = Binder.clearCallingIdentity();
        try {
            UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
            UserInfo ui = um.getProfileParent(callingUser);
            int parentUser = (ui != null) ? ui.id : UserHandle.USER_NULL;

            // Always allow SystemUI/System access.
            return (sForegroundUserId == callingUser) || (sForegroundUserId == parentUser)
                    || (sSystemUiUid == callingUid) || (Process.SYSTEM_UID == callingUid);
        } catch (Exception ex) {
            Log.e(TAG, "checkCallerAllowManagedProfiles: Exception ex=" + ex);
            return false;
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    /**
     * Enforce the context has android.Manifest.permission.BLUETOOTH_ADMIN permission. A
     * {@link SecurityException} would be thrown if neither the calling process or the application
     * does not have BLUETOOTH_ADMIN permission.
     *
     * @param context Context for the permission check.
     */
    public static void enforceAdminPermission(ContextWrapper context) {
        context.enforceCallingOrSelfPermission(android.Manifest.permission.BLUETOOTH_ADMIN,
                "Need BLUETOOTH_ADMIN permission");
    }

    /**
     * Checks whether location is off and must be on for us to perform some operation
     */
    public static boolean blockedByLocationOff(Context context, UserHandle userHandle) {
        return !context.getSystemService(LocationManager.class)
                .isLocationEnabledForUser(userHandle);
    }

    /**
     * Checks that calling process has android.Manifest.permission.ACCESS_COARSE_LOCATION and
     * OP_COARSE_LOCATION is allowed
     */
    public static boolean checkCallerHasCoarseLocation(Context context, AppOpsManager appOps,
            String callingPackage, UserHandle userHandle) {
        if (blockedByLocationOff(context, userHandle)) {
            Log.e(TAG, "Permission denial: Location is off.");
            return false;
        }

        // Check coarse, but note fine
        if (context.checkCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_COARSE_LOCATION)
                        == PackageManager.PERMISSION_GRANTED
                && isAppOppAllowed(appOps, AppOpsManager.OP_FINE_LOCATION, callingPackage)) {
            return true;
        }

        Log.e(TAG, "Permission denial: Need ACCESS_COARSE_LOCATION "
                + "permission to get scan results");
        return false;
    }

    /**
     * Checks that calling process has android.Manifest.permission.ACCESS_COARSE_LOCATION and
     * OP_COARSE_LOCATION is allowed or android.Manifest.permission.ACCESS_FINE_LOCATION and
     * OP_FINE_LOCATION is allowed
     */
    public static boolean checkCallerHasCoarseOrFineLocation(Context context, AppOpsManager appOps,
            String callingPackage, UserHandle userHandle) {
        if (blockedByLocationOff(context, userHandle)) {
            Log.e(TAG, "Permission denial: Location is off.");
            return false;
        }

        if (context.checkCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_FINE_LOCATION)
                        == PackageManager.PERMISSION_GRANTED
                && isAppOppAllowed(appOps, AppOpsManager.OP_FINE_LOCATION, callingPackage)) {
            return true;
        }

        // Check coarse, but note fine
        if (context.checkCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_COARSE_LOCATION)
                        == PackageManager.PERMISSION_GRANTED
                && isAppOppAllowed(appOps, AppOpsManager.OP_FINE_LOCATION, callingPackage)) {
            return true;
        }

        Log.e(TAG, "Permission denial: Need ACCESS_COARSE_LOCATION or ACCESS_FINE_LOCATION"
                + "permission to get scan results");
        return false;
    }

    /**
     * Checks that calling process has android.Manifest.permission.ACCESS_FINE_LOCATION and
     * OP_FINE_LOCATION is allowed
     */
    public static boolean checkCallerHasFineLocation(Context context, AppOpsManager appOps,
            String callingPackage, UserHandle userHandle) {
        if (blockedByLocationOff(context, userHandle)) {
            Log.e(TAG, "Permission denial: Location is off.");
            return false;
        }

        if (context.checkCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_FINE_LOCATION)
                        == PackageManager.PERMISSION_GRANTED
                && isAppOppAllowed(appOps, AppOpsManager.OP_FINE_LOCATION, callingPackage)) {
            return true;
        }

        Log.e(TAG, "Permission denial: Need ACCESS_FINE_LOCATION "
                + "permission to get scan results");
        return false;
    }

    /**
     * Returns true if the caller holds NETWORK_SETTINGS
     */
    public static boolean checkCallerHasNetworkSettingsPermission(Context context) {
        return context.checkCallingOrSelfPermission(android.Manifest.permission.NETWORK_SETTINGS)
                == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Returns true if the caller holds NETWORK_SETUP_WIZARD
     */
    public static boolean checkCallerHasNetworkSetupWizardPermission(Context context) {
        return context.checkCallingOrSelfPermission(
                android.Manifest.permission.NETWORK_SETUP_WIZARD)
                        == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean isLegacyForegroundApp(Context context, String pkgName) {
        return !isMApp(context, pkgName) && isForegroundApp(context, pkgName);
    }

    private static boolean isMApp(Context context, String pkgName) {
        try {
            return context.getPackageManager().getApplicationInfo(pkgName, 0).targetSdkVersion
                    >= Build.VERSION_CODES.M;
        } catch (PackageManager.NameNotFoundException e) {
            // In case of exception, assume M app
        }
        return true;
    }

    public static boolean isQApp(Context context, String pkgName) {
        try {
            return context.getPackageManager().getApplicationInfo(pkgName, 0).targetSdkVersion
                    >= Build.VERSION_CODES.Q;
        } catch (PackageManager.NameNotFoundException e) {
            // In case of exception, assume Q app
        }
        return true;
    }
    /**
     * Return true if the specified package name is a foreground app.
     *
     * @param pkgName application package name.
     */
    private static boolean isForegroundApp(Context context, String pkgName) {
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(1);
        return !tasks.isEmpty() && pkgName.equals(tasks.get(0).topActivity.getPackageName());
    }

    private static boolean isAppOppAllowed(AppOpsManager appOps, int op, String callingPackage) {
        return appOps.noteOp(op, Binder.getCallingUid(), callingPackage)
                == AppOpsManager.MODE_ALLOWED;
    }

    /**
     * Converts {@code millisecond} to unit. Each unit is 0.625 millisecond.
     */
    public static int millsToUnit(int milliseconds) {
        return (int) (TimeUnit.MILLISECONDS.toMicros(milliseconds) / MICROS_PER_UNIT);
    }

    /**
     * Check if we are running in BluetoothInstrumentationTest context by trying to load
     * com.android.bluetooth.FileSystemWriteTest. If we are not in Instrumentation test mode, this
     * class should not be found. Thus, the assumption is that FileSystemWriteTest must exist.
     * If FileSystemWriteTest is removed in the future, another test class in
     * BluetoothInstrumentationTest should be used instead
     *
     * @return true if in BluetoothInstrumentationTest, false otherwise
     */
    public static boolean isInstrumentationTestMode() {
        try {
            return Class.forName("com.android.bluetooth.FileSystemWriteTest") != null;
        } catch (ClassNotFoundException exception) {
            return false;
        }
    }

    /**
     * Throws {@link IllegalStateException} if we are not in BluetoothInstrumentationTest. Useful
     * for ensuring certain methods only get called in BluetoothInstrumentationTest
     */
    public static void enforceInstrumentationTestMode() {
        if (!isInstrumentationTestMode()) {
            throw new IllegalStateException("Not in BluetoothInstrumentationTest");
        }
    }

    /**
     * Check if we are running in PTS test mode. To enable/disable PTS test mode, invoke
     * {@code adb shell setprop persist.bluetooth.pts true/false}
     *
     * @return true if in PTS Test mode, false otherwise
     */
    public static boolean isPtsTestMode() {
        return SystemProperties.getBoolean(PTS_TEST_MODE_PROPERTY, false);
    }

    /**
     * Get uid/pid string in a binder call
     *
     * @return "uid/pid=xxxx/yyyy"
     */
    public static String getUidPidString() {
        return "uid/pid=" + Binder.getCallingUid() + "/" + Binder.getCallingPid();
    }
    public static boolean isDebug() {
        if (IS_DEBUG_BUILD == null) {
            IS_DEBUG_BUILD = Build.TYPE.equals("eng") || Build.TYPE.equals("userdebug");
        }
        return IS_DEBUG_BUILD;
    }
}
