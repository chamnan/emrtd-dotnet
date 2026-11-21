namespace Emrtd;

public sealed class ReadOptions
{
    /// <summary>Try PACE first when EF.CardAccess advertises it (recommended; some chips no longer allow BAC).</summary>
    public bool UsePace { get; init; } = true;

    /// <summary>
    /// Fail the read instead of falling back to BAC when EF.CardAccess offers PACE and PACE was not
    /// established, because it failed or because no offered variant is supported. Off by default.
    /// </summary>
    public bool RequirePace { get; init; }

    /// <summary>Read DG2 (face). It is the largest file, typically 15-30 KB.</summary>
    public bool ReadFace { get; init; } = true;

    /// <summary>Trust store for Passive Authentication. Without it only the SOD signature and hashes are checked.</summary>
    public CscaStore? TrustStore { get; init; }
}

/// <summary>What happened to PACE during a read.</summary>
public enum PaceOutcome
{
    /// <summary>PACE was not tried: the chip has no EF.CardAccess, it lists no PACE, or <see cref="ReadOptions.UsePace"/> is off.</summary>
    NotOffered,
    /// <summary>PACE was established.</summary>
    Succeeded,
    /// <summary>The chip offers PACE, but none of the offered variants is implemented by this library; BAC was used.</summary>
    Unsupported,
    /// <summary>PACE was run and failed (the chip refused a step, or the protocol could not be completed); BAC was used.</summary>
    Failed,
}

/// <summary>The PACE outcome of a read and, when PACE failed, the error that ended it.</summary>
public sealed record PaceResult(PaceOutcome Outcome, string? Error = null);

/// <summary>Thrown by <see cref="DocumentReader.Read"/> when <see cref="ReadOptions.RequirePace"/> is set and PACE was not established.</summary>
public sealed class PaceRequiredException(PaceResult pace, Exception? inner = null)
    : Exception($"PACE is required but was not established ({pace.Outcome}{(pace.Error is null ? "" : ": " + pace.Error)})", inner)
{
    public PaceResult Pace { get; } = pace;
}

public sealed class EmrtdDocument
{
    public required string AccessControl { get; init; }

    /// <summary>
    /// What happened to PACE. A document read over BAC after a failed PACE has <see cref="PaceOutcome.Failed"/>
    /// here, so a caller can tell it apart from a chip that offers no PACE.
    /// </summary>
    public PaceResult Pace { get; init; } = new(PaceOutcome.NotOffered);
    public required string LdsVersion { get; init; }
    public required IReadOnlyList<int> DataGroupsPresent { get; init; }
    public required string[] Mrz { get; init; }
    public FaceImage? Face { get; init; }
    public IReadOnlyDictionary<string, string> PersonalDetails { get; init; } = new Dictionary<string, string>();
    public IReadOnlyDictionary<string, string> DocumentDetails { get; init; } = new Dictionary<string, string>();
    public PassiveAuthenticationResult? PassiveAuthentication { get; init; }

    /// <summary>Raw files as read from the chip, keyed by name ("COM", "SOD", "DG1", ...).</summary>
    public required IReadOnlyDictionary<string, byte[]> RawFiles { get; init; }
}

/// <summary>
/// Reads an ICAO 9303 eMRTD (ePassport or eID card): PACE or BAC with the MRZ key, then the
/// LDS files over secure messaging, then Passive Authentication.
/// </summary>
public sealed class DocumentReader(ICardTransport transport, Action<string>? log = null)
{
    // DG3 (fingerprints) and DG4 (iris) require Extended Access Control with terminal certificates.
    private static readonly int[] EacProtected = [3, 4];

    public EmrtdDocument Read(MrzKey key, ReadOptions? options = null)
    {
        options ??= new ReadOptions();
        var session = new EmrtdSession(transport, log);

        var (accessControl, pace, paceError) = options.UsePace ? TryPace(session, key) : ("", new PaceResult(PaceOutcome.NotOffered), null);
        if (options.RequirePace && pace.Outcome is PaceOutcome.Failed or PaceOutcome.Unsupported)
            throw new PaceRequiredException(pace, paceError);
        if (accessControl.Length == 0)
        {
            session.SelectApplet();
            log?.Invoke("Running BAC...");
            session.StartSecureMessaging(Bac.Authenticate(session, key));
            accessControl = "BAC (3DES)";
        }
        log?.Invoke($"Access control: {accessControl}");

        var raw = new Dictionary<string, byte[]>();
        byte[] com = session.ReadFile(Lds.Com);
        raw["COM"] = com;
        var (ldsVersion, present) = Lds.ParseCom(com);
        log?.Invoke($"LDS {ldsVersion}, data groups: {string.Join(", ", present.Select(g => $"DG{g}"))}");

        foreach (int dg in present.Except(EacProtected))
        {
            if (dg == 2 && !options.ReadFace) continue;
            log?.Invoke($"Reading DG{dg}...");
            if (session.TryReadFile(Lds.DataGroupFileId(dg)) is { } data) raw[$"DG{dg}"] = data;
        }
        if (session.TryReadFile(Lds.Sod) is { } sod) raw["SOD"] = sod;

        var document = Parse(raw, accessControl, options.TrustStore);
        return pace.Outcome == PaceOutcome.NotOffered ? document : WithPace(document, pace);
    }

    private static EmrtdDocument WithPace(EmrtdDocument d, PaceResult pace) => new()
    {
        AccessControl = d.AccessControl,
        LdsVersion = d.LdsVersion,
        DataGroupsPresent = d.DataGroupsPresent,
        Mrz = d.Mrz,
        Face = d.Face,
        PersonalDetails = d.PersonalDetails,
        DocumentDetails = d.DocumentDetails,
        PassiveAuthentication = d.PassiveAuthentication,
        RawFiles = d.RawFiles,
        Pace = pace,
    };

    /// <summary>
    /// Parses files already read from a chip, without a reader: e.g. a dump saved with <c>EmrtdReader --out</c>.
    /// Keys are "COM", "SOD", "DG1".."DG16" (see <see cref="LoadDump"/>).
    /// </summary>
    public static EmrtdDocument Parse(IReadOnlyDictionary<string, byte[]> files, string accessControl = "none (offline)", CscaStore? trustStore = null)
    {
        var dataGroups = files
            .Where(f => f.Key.StartsWith("DG", StringComparison.Ordinal))
            .ToDictionary(f => int.Parse(f.Key.AsSpan(2)), f => f.Value);
        var (ldsVersion, present) = files.TryGetValue("COM", out byte[]? com)
            ? Lds.ParseCom(com)
            : ("", dataGroups.Keys.Order().ToList());

        return new EmrtdDocument
        {
            AccessControl = accessControl,
            LdsVersion = ldsVersion,
            DataGroupsPresent = present,
            Mrz = dataGroups.TryGetValue(1, out byte[]? dg1) ? Lds.ParseDg1(dg1) : [],
            Face = dataGroups.TryGetValue(2, out byte[]? dg2) ? Lds.ParseDg2(dg2) : null,
            PersonalDetails = dataGroups.TryGetValue(11, out byte[]? dg11) ? Lds.ParseDetails(dg11) : new Dictionary<string, string>(),
            DocumentDetails = dataGroups.TryGetValue(12, out byte[]? dg12) ? Lds.ParseDetails(dg12) : new Dictionary<string, string>(),
            PassiveAuthentication = files.TryGetValue("SOD", out byte[]? sod) ? PassiveAuthentication.Verify(sod, dataGroups, trustStore) : null,
            RawFiles = files,
        };
    }

    /// <summary>
    /// Loads a chip dump folder. Files are recognised by their LDS tag, not their name, so dumps from other
    /// tools (JMRTD, ICAO test sets: EF_COM.bin, DG1.bin, 0101.bin, ...) work too. Other files are ignored.
    /// </summary>
    public static Dictionary<string, byte[]> LoadDump(string folder)
    {
        var files = new Dictionary<string, byte[]>();
        foreach (string path in Directory.EnumerateFiles(folder).Order())
        {
            byte[] data = File.ReadAllBytes(path);
            if (Lds.IdentifyFile(data) is { } name) files.TryAdd(name, data);
        }
        return files;
    }

    /// <summary>
    /// Runs PACE if EF.CardAccess offers a supported variant. Returns the description ("" to fall back to BAC),
    /// the outcome, and the exception that ended a failed PACE.
    /// </summary>
    private (string, PaceResult, Exception?) TryPace(EmrtdSession session, MrzKey key)
    {
        byte[]? cardAccess = ReadCardAccess(session);
        if (cardAccess is null)
        {
            log?.Invoke("No EF.CardAccess: chip supports BAC only.");
            return ("", new PaceResult(PaceOutcome.NotOffered), null);
        }

        var infos = PaceInfo.ParseCardAccess(cardAccess);
        log?.Invoke($"EF.CardAccess offers: {(infos.Count == 0 ? "no PACE" : string.Join("; ", infos))}");
        if (infos.Count == 0) return ("", new PaceResult(PaceOutcome.NotOffered), null);
        var pace = infos.FirstOrDefault(i => i.IsSupported);
        if (pace is null)
            return ("", new PaceResult(PaceOutcome.Unsupported, $"no supported variant in: {string.Join("; ", infos)}"), null);

        try
        {
            log?.Invoke($"Running {pace}...");
            session.StartSecureMessaging(Pace.Authenticate(session, key, pace));
            session.SelectApplet();
            return (pace.ToString(), new PaceResult(PaceOutcome.Succeeded), null);
        }
        catch (Exception ex) when (ex is CardException or System.Security.Cryptography.CryptographicException)
        {
            // The chip may still accept BAC; start over from a clean state.
            log?.Invoke($"PACE failed ({ex.Message}); falling back to BAC.");
            session.StopSecureMessaging();
            transport.Reset();
            return ("", new PaceResult(PaceOutcome.Failed, ex.Message), ex);
        }
    }

    private byte[]? ReadCardAccess(EmrtdSession session)
    {
        try
        {
            var select = session.SelectFile(Lds.CardAccess);
            if (select.IsSuccess) return session.ReadFile(Lds.CardAccess);
            return session.ReadFileBySfi(0x1C);
        }
        catch (CardException)
        {
            return null;
        }
    }
}
