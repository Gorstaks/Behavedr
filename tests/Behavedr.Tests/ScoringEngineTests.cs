using Behavedr.Core;
using Behavedr.Core.Models;

namespace Behavedr.Tests;

public class ScoringEngineTests
{
    private readonly ScoringEngine _engine = new();

    [Fact]
    public void CalculateScore_EmptySignals_ReturnsZero()
    {
        var evt = CreateEvent();
        var score = _engine.CalculateScore(evt, []);
        Assert.Equal(0.0, score);
    }

    [Fact]
    public void CalculateScore_SingleSignal_ReturnsWeightTimesConfidence()
    {
        var evt = CreateEvent();
        var signals = new List<Signal> { new("test", 50, 0.8) };
        var score = _engine.CalculateScore(evt, signals);
        Assert.Equal(40.0, score, precision: 2);
    }

    [Fact]
    public void CalculateScore_MultipleSignals_SumsCorrectly()
    {
        var evt = CreateEvent();
        var signals = new List<Signal>
        {
            new("a", 30, 0.5),  // 15
            new("b", 20, 0.8),  // 16
        };
        var score = _engine.CalculateScore(evt, signals);
        Assert.Equal(31.0, score, precision: 2);
    }

    [Fact]
    public void CalculateScore_UserTargeted_AppliesMultiplier()
    {
        var evt = CreateEvent(isUserTargeted: true);
        var signals = new List<Signal> { new("test", 30, 0.5) }; // base=15, *2=30
        var score = _engine.CalculateScore(evt, signals);
        Assert.Equal(30.0, score, precision: 2);
    }

    [Fact]
    public void CalculateScore_PreservesRawScoreAbove100()
    {
        // Scoring engine preserves raw fidelity - does NOT clamp to 100.
        // (100*1.0 + 100*1.0) * 2.0 (user-targeted) = 400
        var evt = CreateEvent(isUserTargeted: true);
        var signals = new List<Signal>
        {
            new("a", 100, 1.0),
            new("b", 100, 1.0),
        };
        var score = _engine.CalculateScore(evt, signals);
        Assert.Equal(400.0, score);
    }

    [Fact]
    public void CalculateScore_ClampsNegativeWeight()
    {
        var evt = CreateEvent();
        var signals = new List<Signal> { new("bad", -50, 0.9) };
        var score = _engine.CalculateScore(evt, signals);
        Assert.Equal(0.0, score); // Clamped weight to 0
    }

    [Fact]
    public void CalculateScore_ClampsConfidenceAboveOne()
    {
        var evt = CreateEvent();
        var signals = new List<Signal> { new("over", 40, 1.5) };
        var score = _engine.CalculateScore(evt, signals);
        Assert.Equal(40.0, score, precision: 2); // confidence clamped to 1.0
    }

    [Fact]
    public void ShouldPresidentKill_AboveThresholdAndTargeted_ReturnsTrue()
    {
        var evt = CreateEvent(isUserTargeted: true);
        Assert.True(_engine.ShouldPresidentKill(96.0, evt));
    }

    [Fact]
    public void ShouldPresidentKill_AboveThresholdNotTargeted_ReturnsFalse()
    {
        var evt = CreateEvent(isUserTargeted: false);
        Assert.False(_engine.ShouldPresidentKill(96.0, evt));
    }

    [Fact]
    public void ShouldPresidentKill_BelowThreshold_ReturnsFalse()
    {
        var evt = CreateEvent(isUserTargeted: true);
        Assert.False(_engine.ShouldPresidentKill(90.0, evt));
    }

    [Fact]
    public void ShouldPresidentKill_ExactlyAtThreshold_ReturnsFalse()
    {
        var evt = CreateEvent(isUserTargeted: true);
        Assert.False(_engine.ShouldPresidentKill(95.0, evt)); // must be > threshold
    }

    [Fact]
    public void CalculateScore_NullEvent_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _engine.CalculateScore(null!, []));
    }

    [Fact]
    public void CalculateScore_NullSignals_Throws()
    {
        var evt = CreateEvent();
        Assert.Throws<ArgumentNullException>(() => _engine.CalculateScore(evt, null!));
    }

    private static DetectionEvent CreateEvent(bool isUserTargeted = false) =>
        new("1234", "test.exe", "test_behavior", DateTime.UtcNow, isUserTargeted, "unit_test");
}
