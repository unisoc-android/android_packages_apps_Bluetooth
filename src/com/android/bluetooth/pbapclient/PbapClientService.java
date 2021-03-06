/*
 * Copyright (c) 2016 The Android Open Source Project
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

package com.android.bluetooth.pbapclient;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothPbapClient;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.provider.CallLog;
import android.util.Log;

import com.android.bluetooth.R;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.sdp.SdpManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides Bluetooth Phone Book Access Profile Client profile.
 *
 * @hide
 */
public class PbapClientService extends ProfileService {
    private static final boolean DBG = Utils.DBG;
    private static final boolean VDBG = Utils.VDBG;

    private static final String TAG = "PbapClientService";
    private static final String SERVICE_NAME = "Phonebook Access PCE";
    // MAXIMUM_DEVICES set to 10 to prevent an excessive number of simultaneous devices.
    private static final int MAXIMUM_DEVICES = 10;
    private Map<BluetoothDevice, PbapClientStateMachine> mPbapClientStateMachineMap =
            new ConcurrentHashMap<>();
    private static PbapClientService sPbapClientService;
    private PbapBroadcastReceiver mPbapBroadcastReceiver = new PbapBroadcastReceiver();
    private int mSdpHandle = -1;

    static final String ACTION_PBAPCLIENT_USER_DOWNLOAD = "action.pbapclient.user.download";

    @Override
    public IProfileServiceBinder initBinder() {
        return new BluetoothPbapClientBinder(this);
    }

    @Override
    protected boolean start() {
        if (VDBG) {
            Log.v(TAG, "onStart");
        }
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED);
        // delay initial download until after the user is unlocked to add an account.
        filter.addAction(Intent.ACTION_USER_UNLOCKED);
        filter.addAction(PbapClientService.ACTION_PBAPCLIENT_USER_DOWNLOAD);
        try {
            registerReceiver(mPbapBroadcastReceiver, filter);
        } catch (Exception e) {
            Log.w(TAG, "Unable to register pbapclient receiver", e);
        }

        removeUncleanAccounts();
        registerSdpRecord();
        setPbapClientService(this);
        return true;
    }

    @Override
    protected boolean stop() {
        setPbapClientService(null);
        cleanUpSdpRecord();
        try {
            unregisterReceiver(mPbapBroadcastReceiver);
        } catch (Exception e) {
            Log.w(TAG, "Unable to unregister pbapclient receiver", e);
        }
        for (PbapClientStateMachine pbapClientStateMachine : mPbapClientStateMachineMap.values()) {
            pbapClientStateMachine.doQuit();
        }
        removeUncleanAccounts();
        return true;
    }

    void cleanupDevice(BluetoothDevice device) {
        if (DBG) Log.d(TAG, "Cleanup device: " + device);
        synchronized (mPbapClientStateMachineMap) {
            PbapClientStateMachine pbapClientStateMachine = mPbapClientStateMachineMap.get(device);
            if (pbapClientStateMachine != null) {
                mPbapClientStateMachineMap.remove(device);
            }
        }
    }

    private void removeUncleanAccounts() {
        // Find all accounts that match the type "pbap" and delete them.
        AccountManager accountManager = AccountManager.get(this);
        Account[] accounts =
                accountManager.getAccountsByType(getString(R.string.pbap_account_type));
        if (VDBG) Log.v(TAG, "Found " + accounts.length + " unclean accounts");
        for (Account acc : accounts) {
            Log.w(TAG, "Deleting " + acc);
            try {
                getContentResolver().delete(CallLog.Calls.CONTENT_URI,
                        CallLog.Calls.PHONE_ACCOUNT_ID + "=?", new String[]{acc.name});
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "Call Logs could not be deleted, they may not exist yet.");
            }
            // The device ID is the name of the account.
            accountManager.removeAccountExplicitly(acc);
        }
    }

    private void registerSdpRecord() {
        SdpManager sdpManager = SdpManager.getDefaultManager();
        if (sdpManager == null) {
            Log.e(TAG, "SdpManager is null");
            return;
        }
        mSdpHandle = sdpManager.createPbapPceRecord(SERVICE_NAME,
                PbapClientConnectionHandler.PBAP_V1_2);
    }

    private void cleanUpSdpRecord() {
        if (mSdpHandle < 0) {
            Log.e(TAG, "cleanUpSdpRecord, SDP record never created");
            return;
        }
        int sdpHandle = mSdpHandle;
        mSdpHandle = -1;
        SdpManager sdpManager = SdpManager.getDefaultManager();
        if (sdpManager == null) {
            Log.e(TAG, "cleanUpSdpRecord failed, sdpManager is null, sdpHandle=" + sdpHandle);
            return;
        }
        Log.i(TAG, "cleanUpSdpRecord, mSdpHandle=" + sdpHandle);
        if (!sdpManager.removeSdpRecord(sdpHandle)) {
            Log.e(TAG, "cleanUpSdpRecord, removeSdpRecord failed, sdpHandle=" + sdpHandle);
        }
    }


    private class PbapBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (DBG) Log.v(TAG, "onReceive" + action);
            if (action.equals(BluetoothDevice.ACTION_ACL_DISCONNECTED)) {
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                if (getConnectionState(device) == BluetoothProfile.STATE_CONNECTED) {
                    disconnect(device);
                }
            } else if (action.equals(Intent.ACTION_USER_UNLOCKED)
                       || action.equals(ACTION_PBAPCLIENT_USER_DOWNLOAD)) {
                for (PbapClientStateMachine stateMachine : mPbapClientStateMachineMap.values()) {
                    stateMachine.resumeDownload();
                }
            }
        }
    }

    /**
     * Handler for incoming service calls
     */
    private static class BluetoothPbapClientBinder extends IBluetoothPbapClient.Stub
            implements IProfileServiceBinder {
        private PbapClientService mService;

        BluetoothPbapClientBinder(PbapClientService svc) {
            mService = svc;
        }

        @Override
        public void cleanup() {
            mService = null;
        }

        private PbapClientService getService() {
            if (!com.android.bluetooth.Utils.checkCaller()) {
                Log.w(TAG, "PbapClient call not allowed for non-active user");
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        @Override
        public boolean connect(BluetoothDevice device) {
            PbapClientService service = getService();
            if (DBG) {
                Log.d(TAG, "PbapClient Binder connect ");
            }
            if (service == null) {
                Log.e(TAG, "PbapClient Binder connect no service");
                return false;
            }
            return service.connect(device);
        }

        @Override
        public boolean disconnect(BluetoothDevice device) {
            PbapClientService service = getService();
            if (service == null) {
                return false;
            }
            return service.disconnect(device);
        }

        @Override
        public List<BluetoothDevice> getConnectedDevices() {
            PbapClientService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getConnectedDevices();
        }

        @Override
        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            PbapClientService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getDevicesMatchingConnectionStates(states);
        }

        @Override
        public int getConnectionState(BluetoothDevice device) {
            PbapClientService service = getService();
            if (service == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return service.getConnectionState(device);
        }

        @Override
        public boolean setPriority(BluetoothDevice device, int priority) {
            PbapClientService service = getService();
            if (service == null) {
                return false;
            }
            return service.setPriority(device, priority);
        }

        @Override
        public int getPriority(BluetoothDevice device) {
            PbapClientService service = getService();
            if (service == null) {
                return BluetoothProfile.PRIORITY_UNDEFINED;
            }
            return service.getPriority(device);
        }


    }

    // API methods
    public static synchronized PbapClientService getPbapClientService() {
        if (sPbapClientService == null) {
            Log.w(TAG, "getPbapClientService(): service is null");
            return null;
        }
        if (!sPbapClientService.isAvailable()) {
            Log.w(TAG, "getPbapClientService(): service is not available");
            return null;
        }
        return sPbapClientService;
    }

    private static synchronized void setPbapClientService(PbapClientService instance) {
        if (VDBG) {
            Log.v(TAG, "setPbapClientService(): set to: " + instance);
        }
        sPbapClientService = instance;
    }

    public boolean connect(BluetoothDevice device) {
        if (device == null) {
            throw new IllegalArgumentException("Null device");
        }
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        if (DBG) Log.d(TAG, "Received request to ConnectPBAPPhonebook " + device.getAddress());
        if (getPriority(device) <= BluetoothProfile.PRIORITY_OFF) {
            return false;
        }

        List<BluetoothDevice> devices = getConnectedDevices();
        if (devices != null && devices.size() > 0) {
            Log.d(TAG, "Already exist device connected");
            return false;
        }

        synchronized (mPbapClientStateMachineMap) {
            PbapClientStateMachine pbapClientStateMachine = mPbapClientStateMachineMap.get(device);
            if (pbapClientStateMachine == null
                    && mPbapClientStateMachineMap.size() < MAXIMUM_DEVICES) {
                pbapClientStateMachine = new PbapClientStateMachine(this, device);
                pbapClientStateMachine.start();
                mPbapClientStateMachineMap.put(device, pbapClientStateMachine);
                return true;
            } else {
                Log.w(TAG, "Received connect request while already connecting/connected.");
                return false;
            }
        }
    }

    boolean disconnect(BluetoothDevice device) {
        if (device == null) {
            throw new IllegalArgumentException("Null device");
        }
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        PbapClientStateMachine pbapClientStateMachine = mPbapClientStateMachineMap.get(device);
        if (pbapClientStateMachine != null) {
            pbapClientStateMachine.disconnect(device);
            return true;

        } else {
            Log.w(TAG, "disconnect() called on unconnected device.");
            return false;
        }
    }

    public List<BluetoothDevice> getConnectedDevices() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        int[] desiredStates = {BluetoothProfile.STATE_CONNECTED};
        return getDevicesMatchingConnectionStates(desiredStates);
    }

    private List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        List<BluetoothDevice> deviceList = new ArrayList<BluetoothDevice>(0);
        for (Map.Entry<BluetoothDevice, PbapClientStateMachine> stateMachineEntry :
                mPbapClientStateMachineMap
                .entrySet()) {
            int currentDeviceState = stateMachineEntry.getValue().getConnectionState();
            for (int state : states) {
                if (currentDeviceState == state) {
                    deviceList.add(stateMachineEntry.getKey());
                    break;
                }
            }
        }
        return deviceList;
    }

    int getConnectionState(BluetoothDevice device) {
        if (device == null) {
            throw new IllegalArgumentException("Null device");
        }
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        PbapClientStateMachine pbapClientStateMachine = mPbapClientStateMachineMap.get(device);
        if (pbapClientStateMachine == null) {
            return BluetoothProfile.STATE_DISCONNECTED;
        } else {
            return pbapClientStateMachine.getConnectionState(device);
        }
    }

    public boolean setPriority(BluetoothDevice device, int priority) {
        if (device == null) {
            throw new IllegalArgumentException("Null device");
        }
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if (DBG) {
            Log.d(TAG, "Saved priority " + device + " = " + priority);
        }
        AdapterService.getAdapterService().getDatabase()
            .setProfilePriority(device, BluetoothProfile.PBAP_CLIENT, priority);
        return true;
    }

    public int getPriority(BluetoothDevice device) {
        if (device == null) {
            throw new IllegalArgumentException("Null device");
        }
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if (DBG) {
        	Log.d(TAG, "get priority " + device + " = " 
                    + AdapterService.getAdapterService().getDatabase().
                        getProfilePriority(device, BluetoothProfile.PBAP_CLIENT));
        }
        return AdapterService.getAdapterService().getDatabase()
                .getProfilePriority(device, BluetoothProfile.PBAP_CLIENT);
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        for (PbapClientStateMachine stateMachine : mPbapClientStateMachineMap.values()) {
            stateMachine.dump(sb);
        }
    }
}
