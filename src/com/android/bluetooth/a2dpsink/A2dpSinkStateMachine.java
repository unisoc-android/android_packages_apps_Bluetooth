/*
 * Copyright (C) 2014 The Android Open Source Project
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
package com.android.bluetooth.a2dpsink;

import android.bluetooth.BluetoothA2dpSink;
import android.bluetooth.BluetoothAudioConfig;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.content.Intent;
import android.media.AudioFormat;
import android.os.Message;
import android.os.ParcelUuid;
import android.util.Log;

import com.android.bluetooth.BluetoothMetricsProto;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.MetricsLogger;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.hfpclient.HeadsetClientService;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.util.List;

public class A2dpSinkStateMachine extends StateMachine {
    static final String TAG = "A2DPSinkStateMachine";
    static final boolean DBG = Utils.isDebug();

    //0->99 Events from Outside
    public static final int CONNECT = 1;
    public static final int DISCONNECT = 2;

    //100->199 Internal Events
    protected static final int CLEANUP = 100;
    private static final int CONNECT_TIMEOUT = 101;

    //200->299 Events from Native
    static final int STACK_EVENT = 200;

    static final int CONNECT_TIMEOUT_MS = 10000;

    protected final BluetoothDevice mDevice;
    protected final byte[] mDeviceAddress;
    protected final A2dpSinkService mService;
    protected final Disconnected mDisconnected;
    protected final Connecting mConnecting;
    protected final Connected mConnected;
    protected final Disconnecting mDisconnecting;

    protected int mMostRecentState = BluetoothProfile.STATE_DISCONNECTED;
    protected BluetoothAudioConfig mAudioConfig = null;

    static final ParcelUuid[] A2DP_SINK_UUID = {
         BluetoothUuid.AudioSink
     };

    A2dpSinkStateMachine(BluetoothDevice device, A2dpSinkService service) {
        super(TAG);
        mDevice = device;
        mDeviceAddress = Utils.getByteAddress(mDevice);
        mService = service;
        if (DBG) Log.d(TAG, device.toString());

        mDisconnected = new Disconnected();
        mConnecting = new Connecting();
        mConnected = new Connected();
        mDisconnecting = new Disconnecting();

        addState(mDisconnected);
        addState(mConnecting);
        addState(mConnected);
        addState(mDisconnecting);

        setInitialState(mDisconnected);
    }

    protected String getConnectionStateChangedIntent() {
        return BluetoothA2dpSink.ACTION_CONNECTION_STATE_CHANGED;
    }

    /**
     * Get the current connection state
     *
     * @return current State
     */
    public int getState() {
        return mMostRecentState;
    }

    /**
     * get current audio config
     */
    BluetoothAudioConfig getAudioConfig() {
        return mAudioConfig;
    }

    /**
     * Get the underlying device tracked by this state machine
     *
     * @return device in focus
     */
    public synchronized BluetoothDevice getDevice() {
        return mDevice;
    }

    /**
     * send the Connect command asynchronously
     */
    public final void connect() {
        sendMessage(CONNECT);
    }

    /**
     * send the Disconnect command asynchronously
     */
    public final void disconnect() {
        sendMessage(DISCONNECT);
    }

    /**
     * Dump the current State Machine to the string builder.
     * @param sb output string
     */
    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mDevice: " + mDevice.getAddress() + "("
                + mDevice.getName() + ") " + this.toString());
    }

    @Override
    protected void unhandledMessage(Message msg) {
        Log.w(TAG, "unhandledMessage in state " + getCurrentState() + "msg.what=" + msg.what);
    }

    class Disconnected extends State {
        @Override
        public void enter() {
            if (DBG) Log.d(TAG, "Enter Disconnected");
            if (mMostRecentState != BluetoothProfile.STATE_DISCONNECTED) {
                sendMessage(CLEANUP);
            }
            onConnectionStateChanged(BluetoothProfile.STATE_DISCONNECTED);
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case STACK_EVENT:
                    processStackEvent((StackEvent) message.obj);
                    return true;
                case CONNECT:
                    if (DBG) Log.d(TAG, "Connect");
                    transitionTo(mConnecting);
                    return true;
                case CLEANUP:
                    mService.removeStateMachine(A2dpSinkStateMachine.this);
                    return true;
            }
            return false;
        }

        void processStackEvent(StackEvent event) {
            switch (event.mType) {
                case StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                    switch (event.mState) {
                        case StackEvent.CONNECTION_STATE_CONNECTED:
                            transitionTo(mConnected);
                            break;
                        case StackEvent.CONNECTION_STATE_DISCONNECTED:
                            sendMessage(CLEANUP);
                            break;
                    }
            }
        }
    }

    class Connecting extends State {
        boolean mIncommingConnection = false;

        @Override
        public void enter() {
            if (DBG) Log.d(TAG, "Enter Connecting");
            onConnectionStateChanged(BluetoothProfile.STATE_CONNECTING);
            sendMessageDelayed(CONNECT_TIMEOUT, CONNECT_TIMEOUT_MS);

            if (!mIncommingConnection) {
                mService.connectA2dpNative(mDeviceAddress);
            }

            super.enter();
        }

        @Override
        public boolean processMessage(Message message) {
            log("processMessage message.what=: " + message.what);
            switch (message.what) {
                case STACK_EVENT:
                    processStackEvent((StackEvent) message.obj);
                    return true;
                case CONNECT_TIMEOUT:
                    transitionTo(mDisconnected);
                    return true;
            }
            return false;
        }

        void processStackEvent(StackEvent event) {
            log("processStackEvent event=:" + event);
            switch (event.mType) {
                case StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                    switch (event.mState) {
                        case StackEvent.CONNECTION_STATE_CONNECTED:
                            transitionTo(mConnected);
                            break;
                        case StackEvent.CONNECTION_STATE_DISCONNECTED:
                            transitionTo(mDisconnected);
                            break;
                    }
            }
        }
        @Override
        public void exit() {
            removeMessages(CONNECT_TIMEOUT);
        }

    }

    class Connected extends State {
        @Override
        public void enter() {
            if (DBG) Log.d(TAG, "Enter Connected");

            if (is_other_connExist()) {
                if (DBG) Log.d(TAG, 
                        "Connected, we got an other device connected.So disconnect currentDevice:"
                        + mDevice);
                mService.disconnect(mDevice);
            } else {
                AdapterService adapterService = AdapterService.getAdapterService();
                if(adapterService != null)adapterService.disableAutoTryConnect();

                mService.setPriority(mDevice,BluetoothProfile.PRIORITY_AUTO_CONNECT);

                onConnectionStateChanged(BluetoothProfile.STATE_CONNECTED);
            }
        }

        private boolean is_other_connExist() {
            //check a2dp connection:
            //if we got another connection from a different device, 
            //   we need diconnect the curr Device
            List<BluetoothDevice> a2dpConnDevList= mService.getConnectedDevices();
            if(a2dpConnDevList != null && a2dpConnDevList.size() >0) {
                if (DBG) Log.d(TAG, "Connected a2dpConnDevList:" +a2dpConnDevList);

                if(a2dpConnDevList.indexOf(mDevice) <0){
                    return true;
                }
            }

            //check hfp connection:
            //if we got another connection from a different device, 
            //   we need diconnect the curr Device
            HeadsetClientService  hscService = HeadsetClientService.getHeadsetClientService();
            log("Enter Connected: hscService:"+hscService);
            if(hscService != null){
                List<BluetoothDevice> hfConnDevList= hscService.getConnectedDevices();

                if (DBG) Log.d(TAG, "Connected:hfConnDevList="+ hfConnDevList);

                if(hfConnDevList != null && hfConnDevList.size() > 0){
                    if(hfConnDevList.indexOf(mDevice) <0) {
                        return true;
                    }
                }
            }

            return false;
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case DISCONNECT:
                    transitionTo(mDisconnecting);
                    mService.disconnectA2dpNative(mDeviceAddress);
                    return true;
                case STACK_EVENT:
                    processStackEvent((StackEvent) message.obj);
                    return true;
            }
            return false;
        }

        void processStackEvent(StackEvent event) {
            switch (event.mType) {
                case StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                    switch (event.mState) {
                        case StackEvent.CONNECTION_STATE_DISCONNECTING:
                            transitionTo(mDisconnecting);
                            break;
                        case StackEvent.CONNECTION_STATE_DISCONNECTED:
                            transitionTo(mDisconnected);
                            break;
                    }
                    break;
                case StackEvent.EVENT_TYPE_AUDIO_CONFIG_CHANGED:
                    mAudioConfig = new BluetoothAudioConfig(event.mSampleRate, event.mChannelCount,
                            AudioFormat.ENCODING_PCM_16BIT);
                    break;
            }
        }
    }

    protected class Disconnecting extends State {
        @Override
        public void enter() {
            if (DBG) Log.d(TAG, "Enter Disconnecting");
            onConnectionStateChanged(BluetoothProfile.STATE_DISCONNECTING);
            transitionTo(mDisconnected);
        }
    }

    protected void onConnectionStateChanged(int currentState) {
        if (mMostRecentState == currentState) {
            return;
        }
        if (currentState == BluetoothProfile.STATE_CONNECTED) {
            MetricsLogger.logProfileConnectionEvent(BluetoothMetricsProto.ProfileId.A2DP_SINK);
        }
        if (DBG) {
            Log.d(TAG, "Connection state " + mDevice + ": " + mMostRecentState + "->"
                    + currentState);
        }
        Intent intent = new Intent(BluetoothA2dpSink.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, mMostRecentState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, currentState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        mMostRecentState = currentState;
        mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }
}
