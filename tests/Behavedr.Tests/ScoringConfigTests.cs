using Behavedr.Core;

namespace Behavedr.Tests;

public class ScoringConfigTests
{
    [Fact]
    public void Default_IsValid()
    {
        Assert.True(ScoringConfig.Default.IsValid());
    }

    [Fact]
    public void Custom_ValidConfig_IsValid()
    {
        var config = new ScoringConfig
        {
            UserTargetedMultiplier = 3.0,
            PresidentKillThreshold = 80.0,
            HighScoreAlertThreshold = 40.0,
        };
        Assert.True(config.IsValid());
    }

    [Fact]
    public void Invalid_ZeroMultiplier()
    {
        var config = new ScoringConfig { UserTargetedMultiplier = 0.0 };
        Assert.False(config.IsValid());
    }

    [Fact]
    public void Invalid_NegativeThreshold()
    {
        var config = new ScoringConfig { PresidentKillThreshold = -1.0 };
        Assert.False(config.IsValid());
    }

    [Fact]
    public void Invalid_AlertAboveKill()
    {
        var config = new ScoringConfig
        {
            PresidentKillThreshold = 50.0,
            HighScoreAlertThreshold = 60.0,
        };
        Assert.False(config.IsValid());
    }

    [Fact]
    public void Invalid_MultiplierTooHigh()
    {
        var config = new ScoringConfig { UserTargetedMultiplier = 11.0 };
        Assert.False(config.IsValid());
    }

    [Fact]
    public void ScoringEngine_UsesCustomConfig()
    {
        var config = new ScoringConfig
        {
            UserTargetedMultiplier = 3.0,
            PresidentKillThreshold = 80.0,
        };
        var engine = new ScoringEngine(config);

        Assert.Equal(80.0, engine.PresidentKillThreshold);
        Assert.Equal(3.0, engine.UserTargetedMultiplier);
    }
}
