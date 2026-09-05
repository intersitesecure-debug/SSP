// File: tests/SSP.Tests/Activation/SspSecurityEventSinkTaxonomyTests.cs
//
// P5 hardening (event-log taxonomy review): the Windows Application-log
// presentation of SSP licensing security events is a stable operational
// contract, not an accident of the first implementation. These tests pin the
// reviewed taxonomy:
//
//   * every licensing event type maps to a documented entry type (severity);
//   * the severity classes are exactly as reviewed (no event type is
//     silently raised or lowered);
//   * event ids are stable, unique and outside the system-defined range;
//   * the taxonomy covers the full event vocabulary, and the exhaustive
//     switch in SspSecurityEventSink fails compilation when the library
//     appends a new event type, so the review cannot go stale silently.

using System.Diagnostics;
using System.Runtime.Versioning;
using SSP.Activation;
using SSP.Server.Activation;

namespace SSP.Tests.Activation;

[SupportedOSPlatform("windows")]
public class SspSecurityEventSinkTaxonomyTests
{
    [Fact]
    public void Taxonomy_MapsEveryDefinedEventType_ToTheReviewedSeverity()
    {
        foreach (var eventType in Enum.GetValues<LicenseSecurityEventType>())
        {
            var actual = LicensingEventLogTaxonomy.EntryTypeFor(eventType);

            var expected = eventType switch
            {
                LicenseSecurityEventType.LicenseLoaded => EventLogEntryType.Information,
                LicenseSecurityEventType.LicenseValidated => EventLogEntryType.Information,
                LicenseSecurityEventType.LicenseValidationFailed => EventLogEntryType.Warning,
                LicenseSecurityEventType.InvalidSignature => EventLogEntryType.Warning,
                LicenseSecurityEventType.LicenseExpired => EventLogEntryType.Warning,
                LicenseSecurityEventType.LicenseBindingFailed => EventLogEntryType.Warning,
                LicenseSecurityEventType.LicenseRevoked => EventLogEntryType.Warning,
                LicenseSecurityEventType.LicenseLockdownActivated => EventLogEntryType.Warning,
                LicenseSecurityEventType.LicenseLockdownCleared => EventLogEntryType.Information,
                LicenseSecurityEventType.LicenseSuperseded => EventLogEntryType.Information,
                LicenseSecurityEventType.ProtectedOperationDenied => EventLogEntryType.Warning,
                LicenseSecurityEventType.ActivationRequired => EventLogEntryType.Information,
                LicenseSecurityEventType.LicenseActivated => EventLogEntryType.Information,
                _ => throw new Xunit.Sdk.XunitException($"No reviewed severity for {eventType}"),
            };

            Assert.True(actual == expected, $"Event type {eventType} mapped to {actual}, expected {expected}");
        }
    }

    [Fact]
    public void Taxonomy_NormalLifecycleEvents_AreInformation_DenialsAreWarning_AndNothingIsError()
    {
        // Information: normal lifecycle transitions only.
        Assert.Equal(EventLogEntryType.Information, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseLoaded));
        Assert.Equal(EventLogEntryType.Information, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseValidated));
        Assert.Equal(EventLogEntryType.Information, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseLockdownCleared));
        Assert.Equal(EventLogEntryType.Information, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseSuperseded));
        Assert.Equal(EventLogEntryType.Information, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.ActivationRequired));
        Assert.Equal(EventLogEntryType.Information, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseActivated));

        // Warning: every denial / operator-actionable failure state.
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseValidationFailed));
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.InvalidSignature));
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseExpired));
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseBindingFailed));
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseRevoked));
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.LicenseLockdownActivated));
        Assert.Equal(EventLogEntryType.Warning, LicensingEventLogTaxonomy.EntryTypeFor(LicenseSecurityEventType.ProtectedOperationDenied));

        // Error is deliberately never used: the sink is best-effort and
        // licensing denial states are operational, not crashes.
        foreach (var eventType in Enum.GetValues<LicenseSecurityEventType>())
        {
            Assert.NotEqual(EventLogEntryType.Error, LicensingEventLogTaxonomy.EntryTypeFor(eventType));
        }
    }

    [Fact]
    public void Taxonomy_EventIds_AreStable_Unique_AndOutsideTheSystemRange()
    {
        var seen = new HashSet<int>();

        foreach (var eventType in Enum.GetValues<LicenseSecurityEventType>())
        {
            var eventId = LicensingEventLogTaxonomy.EventIdFor(eventType);

            // Stable formula: base + enum value, documented in the sink.
            Assert.Equal(LicensingEventLogTaxonomy.EventIdBase + (int)eventType, eventId);

            // Outside the system-defined range, so no collision with
            // SCM / ServiceBase / runtime entries.
            Assert.True(eventId >= 1000, $"Event id {eventId} for {eventType} fell into the system-defined range");

            Assert.True(seen.Add(eventId), $"Event id {eventId} for {eventType} was not unique");
        }

        // The reviewed range covers the whole current vocabulary exactly once.
        Assert.Equal(Enum.GetValues<LicenseSecurityEventType>().Length, seen.Count);
    }

    [Fact]
    public void Taxonomy_CoversTheFullCurrentEventVocabulary()
    {
        // Pins the reviewed vocabulary: when the library appends an event
        // type this assertion fails (and so does the exhaustive switch in the
        // sink), which is exactly the signal that the taxonomy needs review.
        var expected = Enum.GetValues<LicenseSecurityEventType>();
        Assert.Equal(13, expected.Length);

        Assert.Contains(LicenseSecurityEventType.LicenseLoaded, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseValidated, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseValidationFailed, expected);
        Assert.Contains(LicenseSecurityEventType.InvalidSignature, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseExpired, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseBindingFailed, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseRevoked, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseLockdownActivated, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseLockdownCleared, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseSuperseded, expected);
        Assert.Contains(LicenseSecurityEventType.ProtectedOperationDenied, expected);
        Assert.Contains(LicenseSecurityEventType.ActivationRequired, expected);
        Assert.Contains(LicenseSecurityEventType.LicenseActivated, expected);
    }
}
