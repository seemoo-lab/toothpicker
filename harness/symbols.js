// This file defines common symbols required for fuzzing.
// Symbols change with each iOS version. Note that pre-A12 devices
// and A12+ devices have different binaries. For example, an iPhone
// 7 and iPhone 8 are using the same bluetoothd binary on the same
// iOS version, but an iPhone 11 is using another one.

exports.symbols = {

    // iOS 13.3, pre A12
    symbols_ios_13_3: {
        allocateACLConnection: 0xc81a0,
        allocateLEConnection: 0xc854c,
        l2cap_send_packet: 0x1024b4,
        OI_SignalMan_Recv: 0x10b52c,
        OI_L2CAP_Recv: 0x1031ec,
        magnet_l2cap_recv: 0x403d8,
        magic_pairing_l2cap_recv: 0x129110,
        bt_forceDisconnect: 0xadb18,
        ACL_reception_handler: 0xcd824,
        OI_HCI_ReleaseConnection: 0x0c87e0,
        create_connection: 0x11ba24,
        _GATT_LE_DisconnectedCB: 0x114d60,
        ReadRemoteVersionInformationCB: 0x12117c,
        hci_handle_exists: 0x0c7df4,
        LE_ReadRemoteVersionInformationComplete: 0x11c948,
        OI_LP_ConnectionAdded: 0xf02b8,
        btstack_free: 0x583e4,
        startSecurityPolicyEnforcement: 0x153274,
        registerTimeout: 0x151698, 
    },

    // iOS 13.3.1, pre A12
    symbols_ios_13_3_1: {
        allocateACLConnection: 0xc7f48,                                
        allocateLEConnection: 0xc82f4, // possible_allocateLEConnection
        l2cap_send_packet: 0x10225c,                                   
        OI_SignalMan_Recv: 0x10b2d4,                                   
        OI_L2CAP_Recv: 0x102f94,                                       
        magnet_l2cap_recv: 0x40180,                                    
        magic_pairing_l2cap_recv: 0x128eb8,                            
        bt_forceDisconnect: 0xad8c0,                                   
        ACL_reception_handler: 0xcd5cc,                                
        OI_HCI_ReleaseConnection: 0xc8588,                             
        create_connection: 0x11b7cc,                                   
        _GATT_LE_DisconnectedCB: 0x114b08,                             
        ReadRemoteVersionInformationCB: 0x120f24,                      
        hci_handle_exists: 0xc7b9c,                                    
        LE_ReadRemoteVersionInformationComplete: 0xc11c6f0,            
        OI_LP_ConnectionAdded: 0xf0060,
        btstack_free: 0x5818c,
        startSecurityPolicyEnforcement: 0x152e98, // here called SignalMan_NewPolicyManager, looks as it was extended in 13.5b4
        registerTimeout: 0x151440, //here register_timeout_callback_function
        OI_L2CAP_WriteMBUF: 0xebe40,
    },

    // iOS 13.4 B4, pre A12
    symbols_ios_13_5_beta4: {
        allocateACLConnection: 0xf10b8,
        allocateLEConnection: 0xf1464,
        OI_SignalMan_Recv: 0x134c40,
        OI_L2CAP_Recv: 0x12c70c,
        bt_forceDisconnect: 0xd6644,
        ACL_reception_handler: 0xf66c8,
        OI_HCI_ReleaseConnection: 0xf16f8,
        create_connection: 0x1454b4,
        _GATT_LE_DisconnectedCB: 0x13e5a8,
        ReadRemoteVersionInformationCB: 0x14b17c,
        hci_handle_exists: 0xf0d0c,
        LE_ReadRemoteVersionInformationComplete: 0x1465b4,
        OI_LP_ConnectionAdded: 0x119820,
        btstack_free: 0x806b0,
        startSecurityPolicyEnforcement: 0x17da00,
        enforceLinkPolicy: 0x17e120,
        registerTimeout: 0x017bc1c, 
        ble_adv_stuff: 0x3e1978,
        coreDumpPacketCounter: 0x2d4ec8,
        OI_L2CAP_WriteMBUF: 0x115634,
        is_internal_build: 0x07f428,
    },

    // iOS 13.5, pre A12
    symbols_ios_13_5: {
        ACL_reception_handler: 0x1013f8,
        LE_ReadRemoteVersionInformationComplete: 0x151390,
        OI_HCI_ReleaseConnection: 0xfc428,
        OI_L2CAP_Recv: 0x13743c,
        OI_LP_ConnectionAdded: 0x124550,
        OI_SignalMan_Recv: 0x13f970,
        ReadRemoteVersionInformationCB: 0x155f58,
        _GATT_LE_DisconnectedCB: 0x149384,
        allocateACLConnection: 0xfbde8,
        allocateLEConnection: 0xfc194,
        bt_forceDisconnect: 0xe1374,
        btstack_free: 0xdaa80,
        create_connection: 0x150290,
        hci_handle_exists: 0xfba3c,
        registerTimeout: 0x186af8,
        startSecurityPolicyEnforcement: 0x1888dc
    },

    // iOS 13.6, pre A12
    symbols_ios_13_6_iphone8: {
        allocateACLConnection: 0xec940,
        allocateLEConnection: 0xeccec,
        OI_SignalMan_Recv: 0x1310dc,
        OI_L2CAP_Recv: 0x128b38,
        bt_forceDisconnect: 0xd1f58,
        ACL_reception_handler: 0xf1f20,
        OI_HCI_ReleaseConnection: 0xecf80,
        create_connection: 0x141a20,
        _GATT_LE_DisconnectedCB: 0x13ab14,
        ReadRemoteVersionInformationCB: 0x1476b4,
        hci_handle_exists: 0xec594,
        LE_ReadRemoteVersionInformationComplete: 0x142b20,
        OI_LP_ConnectionAdded: 0x115a60,
        //btstack_free: 0x7bcd8,
        startSecurityPolicyEnforcement: 0x179f28,
        enforceLinkPolicy: 0x17a648,
        registerTimeout: 0x178144,
        ble_adv_stuff: 0x3da914,
        coreDumpPacketCounter: 0x2cf820,
        OI_L2CAP_WriteMBUF: 0x1117c8,
        is_internal_build: 0x7aa50,
    },

    // iOS 13.5, A12+
    symbols_ios_13_3_iphone11: {
        allocateACLConnection: 0xcaec4,
        allocateLEConnection: 0xcb27c,
        OI_SignalMan_Recv: 0x10f9d8,
        OI_L2CAP_Recv: 0xf3a24,
        bt_forceDisconnect: 0xb0144,
        ACL_reception_handler: 0xd0908,
        OI_HCI_ReleaseConnection: 0xcb518,
        create_connection: 0x120290,
        _GATT_LE_DisconnectedCB: 0x119570,
        ReadRemoteVersionInformationCB: 0x125ae4,
        hci_handle_exists: 0xcab04,
        LE_ReadRemoteVersionInformationComplete: 0x1211d0,
        OI_LP_ConnectionAdded: 0xf3fc4,
        btstack_free: 0x58ffc,
        startSecurityPolicyEnforcement: 0x158a5c, //significantly changed, BinDiff thinks it's 3C580 with low conf
        enforceLinkPolicy: 0x158f64,
        registerTimeout: 0x156de0,
        ble_adv_stuff: 0x3a4bb4,
        coreDumpPacketCounter: 0x2a5aa0,
        OI_L2CAP_WriteMBUF: 0xefd20,
        is_internal_build: 0x57cc8,
    },

    // iOS 13.5, A12+
    symbols_ios_13_5_iphonese2: {
        allocateACLConnection: 0x1078d0,
        allocateLEConnection: 0x107c88,
        OI_SignalMan_Recv: 0x14d3d4,
        OI_L2CAP_Recv: 0x144b1c,
        bt_forceDisconnect: 0xec1b8,
        ACL_reception_handler: 0x10d320,
        OI_HCI_ReleaseConnection: 0x107f24,
        create_connection: 0x15e2b8,
        _GATT_LE_DisconnectedCB: 0x1571ec,
        ReadRemoteVersionInformationCB: 0x1640b0,
        hci_handle_exists: 0x107510,
        LE_ReadRemoteVersionInformationComplete: 0x15f3e8,
        OI_LP_ConnectionAdded: 0x1316b0,
        btstack_free: 0x93e10,
        startSecurityPolicyEnforcement: 0x197d60,
        enforceLinkPolicy: 0x1984ac,
        registerTimeout: 0x195ee4,
        ble_adv_stuff: 0x414674,
        coreDumpPacketCounter: 0x3002a4,
        OI_L2CAP_WriteMBUF: 0x12d3c8,
        is_internal_build: 0x92b04,
    },

};
