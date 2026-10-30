using Behavedr.Core.Models;

namespace Behavedr.Tests;

public class SignalTests
{
    [Fact]
    public void EffectiveScore_NormalValues()
    {
        var signal = new Signal("test", 50, 0.8);
        Assert.Equal(40.0, signal.EffectiveScore, precision: 2);
    }

    [Fact]
    public void EffectiveScore_ClampsNegativeWeight()
    {
        var signal = new Signal("neg", -20, 0.5);
        Assert.Equal(0.0, signal.EffectiveScore);
    }

    [Fact]
    public void EffectiveScore_ClampsHighConfidence()
    {
        var signal = new Signal("high", 60, 2.0);
        Assert.Equal(60.0, signal.EffectiveScore, precision: 2); // confidence clamped to 1
    }

    [Fact]
    public void EffectiveScore_ClampsWeightAbove100()
    {
        var signal = new Signal("over", 150, 0.5);
        Assert.Equal(50.0, signal.EffectiveScore, precision: 2); // weight clamped to 100
    }
}
