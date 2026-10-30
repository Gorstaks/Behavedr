namespace Behavedr.Core.Response;

using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// User-mode Windows Filtering Platform (WFP) engine for network isolation.
/// Uses fwpuclnt.dll filter APIs - real WFP layers at ALE_AUTH_CONNECT / ALE_AUTH_RECV_ACCEPT.
/// Does <b>not</b> require a callout driver or WHQL signing.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsWfpEngine : IDisposable
{
    private readonly ILogger _logger;
    private IntPtr _engine = IntPtr.Zero;
    private readonly List<Guid> _filterIds = new();
    private readonly List<IntPtr> _ownedNative = new(); // condition value buffers
    private readonly object _lock = new();
    private bool _disposed;
    private const int MaxFilters = 100;

    // Stable project sub-layer
    private static readonly Guid BehavedrSubLayerKey = new("A7C4E8F1-2B3D-4E5F-9A0B-1C2D3E4F5A6C");
    private static readonly Guid FwpmLayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid FwpmLayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    private static readonly Guid FwpmLayerAleAuthRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-ffd55ca401d7");
    private static readonly Guid FwpmLayerAleAuthRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    private static readonly Guid FwpmConditionIpRemoteAddressV4 = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid FwpmConditionIpRemoteAddressV6 = new("246e1d8f-40f3-4f3b-b6bb-b5b501ffd1f7");

    public bool IsOpen => _engine != IntPtr.Zero;

    public WindowsWfpEngine(ILogger? logger = null)
    {
        _logger = logger ?? NullLogger.Instance;
    }

    public bool TryOpen()
    {
        if (_engine != IntPtr.Zero)
            return true;

        uint result = FwpmEngineOpen0(
            serverName: null,
            authnService: RPC_C_AUTHN_WINNT,
            authIdentity: IntPtr.Zero,
            session: IntPtr.Zero,
            engineHandle: out _engine);

        if (result != 0 || _engine == IntPtr.Zero)
        {
            _logger.LogWarning("[WFP] FwpmEngineOpen0 failed: 0x{Code:X8}", result);
            _engine = IntPtr.Zero;
            return false;
        }

        EnsureSubLayer();
        _logger.LogInformation("[WFP] Filter engine open");
        return true;
    }

    /// <summary>
    /// Block remote address at ALE_AUTH_CONNECT (outbound) and ALE_AUTH_RECV_ACCEPT (inbound).
    /// </summary>
    public bool BlockRemoteAddress(IPAddress address, string comment)
    {
        if (!TryOpen())
            return false;

        lock (_lock)
        {
            if (_filterIds.Count >= MaxFilters - 1)
            {
                _logger.LogWarning("[WFP] Filter limit {Max} reached", MaxFilters);
                return false;
            }
        }

        bool isV6 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        bool outOk = AddBlockFilter(
            address, isV6,
            isV6 ? FwpmLayerAleAuthConnectV6 : FwpmLayerAleAuthConnectV4,
            isV6 ? FwpmConditionIpRemoteAddressV6 : FwpmConditionIpRemoteAddressV4,
            comment + " (out)");
        bool inOk = AddBlockFilter(
            address, isV6,
            isV6 ? FwpmLayerAleAuthRecvAcceptV6 : FwpmLayerAleAuthRecvAcceptV4,
            isV6 ? FwpmConditionIpRemoteAddressV6 : FwpmConditionIpRemoteAddressV4,
            comment + " (in)");

        if (outOk || inOk)
        {
            _logger.LogWarning("[WFP] Blocked remote {Ip} out={Out} in={In}", address, outOk, inOk);
            return true;
        }
        return false;
    }

    private bool AddBlockFilter(IPAddress address, bool isV6, Guid layerKey, Guid condField, string comment)
    {
        var filterKey = Guid.NewGuid();
        IntPtr filterPtr = IntPtr.Zero;
        IntPtr namePtr = IntPtr.Zero;
        IntPtr descPtr = IntPtr.Zero;
        IntPtr condPtr = IntPtr.Zero;
        IntPtr condValueNative = IntPtr.Zero;
        try
        {
            namePtr = Marshal.StringToHGlobalUni($"Behavedr block {address}");
            descPtr = Marshal.StringToHGlobalUni(comment.Length > 200 ? comment[..200] : comment);

            condValueNative = AllocConditionValue(address, isV6, out var condValue);
            if (condValueNative == IntPtr.Zero && isV6)
                return false;

            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = condField,
                matchType = FWP_MATCH_EQUAL,
                conditionValue = condValue,
            };
            condPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
            Marshal.StructureToPtr(condition, condPtr, false);

            var filter = new FWPM_FILTER0
            {
                filterKey = filterKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = namePtr, description = descPtr },
                flags = 0,
                providerKey = IntPtr.Zero,
                providerData = default,
                layerKey = layerKey,
                subLayerKey = BehavedrSubLayerKey,
                weight = new FWP_VALUE0 { type = FWP_UINT8, anon = new FWP_VALUE0_UNION { uint8 = 0x0F } },
                numFilterConditions = 1,
                filterCondition = condPtr,
                action = new FWPM_ACTION0 { type = FWP_ACTION_BLOCK, filterType = Guid.Empty },
                rawContext = 0,
                reserved = IntPtr.Zero,
                filterId = 0,
                effectiveWeight = new FWP_VALUE0 { type = FWP_EMPTY },
            };

            filterPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_FILTER0>());
            Marshal.StructureToPtr(filter, filterPtr, false);

            uint hr = FwpmFilterAdd0(_engine, filterPtr, IntPtr.Zero, out _);
            if (hr != 0)
            {
                _logger.LogDebug("[WFP] FwpmFilterAdd0 failed 0x{Hr:X8} layer={Layer}", hr, layerKey);
                // free cond value only on failure; on success keep for filter lifetime
                if (condValueNative != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(condValueNative);
                    condValueNative = IntPtr.Zero;
                }
                return false;
            }

            lock (_lock)
            {
                _filterIds.Add(filterKey);
                if (condValueNative != IntPtr.Zero)
                {
                    _ownedNative.Add(condValueNative);
                    condValueNative = IntPtr.Zero; // ownership transferred
                }
            }
            return true;
        }
        finally
        {
            if (filterPtr != IntPtr.Zero) Marshal.FreeHGlobal(filterPtr);
            if (condPtr != IntPtr.Zero) Marshal.FreeHGlobal(condPtr);
            if (namePtr != IntPtr.Zero) Marshal.FreeHGlobal(namePtr);
            if (descPtr != IntPtr.Zero) Marshal.FreeHGlobal(descPtr);
            if (condValueNative != IntPtr.Zero) Marshal.FreeHGlobal(condValueNative);
        }
    }

    private static IntPtr AllocConditionValue(IPAddress address, bool isV6, out FWP_CONDITION_VALUE0 value)
    {
        if (!isV6)
        {
            var bytes = address.GetAddressBytes();
            // host-order uint for FWP_V4_ADDR_AND_MASK.addr
            uint addr = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
            var v4 = new FWP_V4_ADDR_AND_MASK { addr = addr, mask = 0xFFFFFFFF };
            IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<FWP_V4_ADDR_AND_MASK>());
            Marshal.StructureToPtr(v4, p, false);
            value = new FWP_CONDITION_VALUE0
            {
                type = FWP_V4_ADDR_MASK,
                anon = new FWP_CONDITION_VALUE0_UNION { pointer = p },
            };
            return p;
        }
        else
        {
            // FWP_V6_ADDR_AND_MASK: 16-byte addr + prefixLength
            var bytes = address.GetAddressBytes();
            int size = 16 + 1 + 3; // addr + prefix + pad
            IntPtr p = Marshal.AllocHGlobal(size);
            // zero
            for (int i = 0; i < size; i++) Marshal.WriteByte(p, i, 0);
            Marshal.Copy(bytes, 0, p, Math.Min(16, bytes.Length));
            Marshal.WriteByte(p, 16, 128); // /128 exact host
            value = new FWP_CONDITION_VALUE0
            {
                type = FWP_V6_ADDR_MASK,
                anon = new FWP_CONDITION_VALUE0_UNION { pointer = p },
            };
            return p;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_engine == IntPtr.Zero)
        {
            FreeOwned();
            return;
        }

        lock (_lock)
        {
            foreach (var id in _filterIds)
            {
                try
                {
                    var key = id;
                    FwpmFilterDeleteByKey0(_engine, ref key);
                }
                catch { /* best-effort */ }
            }
            _filterIds.Clear();
        }

        FwpmEngineClose0(_engine);
        _engine = IntPtr.Zero;
        FreeOwned();
    }

    private void FreeOwned()
    {
        lock (_lock)
        {
            foreach (var p in _ownedNative)
            {
                try { Marshal.FreeHGlobal(p); } catch { /* ignore */ }
            }
            _ownedNative.Clear();
        }
    }

    private void EnsureSubLayer()
    {
        var namePtr = Marshal.StringToHGlobalUni("Behavedr Isolation");
        var descPtr = Marshal.StringToHGlobalUni("Behavedr EDR network isolation sub-layer");
        try
        {
            var sub = new FWPM_SUBLAYER0
            {
                subLayerKey = BehavedrSubLayerKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = namePtr, description = descPtr },
                flags = 0,
                providerKey = IntPtr.Zero,
                providerData = default,
                weight = 0x8000,
            };
            IntPtr subPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_SUBLAYER0>());
            try
            {
                Marshal.StructureToPtr(sub, subPtr, false);
                // Already exists -> ignore error (FWP_E_ALREADY_EXISTS)
                FwpmSubLayerAdd0(_engine, subPtr, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(subPtr);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
        }
    }

    // --- P/Invoke (fwpuclnt.dll) ---

    private const uint RPC_C_AUTHN_WINNT = 10;
    private const ushort FWP_EMPTY = 0;
    private const ushort FWP_UINT8 = 1;
    private const ushort FWP_V4_ADDR_MASK = 12;
    private const ushort FWP_V6_ADDR_MASK = 13;
    private const uint FWP_MATCH_EQUAL = 0;
    // FWP_ACTION_BLOCK | FWP_ACTION_FLAG_TERMINATING
    private const uint FWP_ACTION_BLOCK = 0x00001001;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_DISPLAY_DATA0
    {
        public IntPtr name;
        public IntPtr description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    private struct FWP_VALUE0_UNION
    {
        [FieldOffset(0)] public byte uint8;
        [FieldOffset(0)] public uint uint32;
        [FieldOffset(0)] public IntPtr pointer;
    }

    // FWP_DATA_TYPE is 4 bytes; union follows (aligned)
    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_VALUE0
    {
        public ushort type;
        public ushort reserved;
        public FWP_VALUE0_UNION anon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    private struct FWP_CONDITION_VALUE0_UNION
    {
        [FieldOffset(0)] public uint uint32;
        [FieldOffset(0)] public IntPtr pointer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_CONDITION_VALUE0
    {
        public ushort type;
        public ushort reserved;
        public FWP_CONDITION_VALUE0_UNION anon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public ulong rawContext;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, IntPtr subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);
}
