function calculateCVSS2BaseScore(confidentialityImpact, integrityImpact, availabilityImpact, accessVector, accessComplexity, authentication) {
    // Define the coefficients
    const accessVectorCoefficients = {
      'L': 0.395,
      'AN': 0.646,
      'N': 1.0
    };
    
    const accessComplexityCoefficients = {
      'H': 0.35,
      'M': 0.61,
      'L': 0.71
    };
    
    const authenticationCoefficients = {
      'M': 0.45,
      'S': 0.56,
      'N': 0.704
    };
    
    const impactCoefficients = {
      'N': 0.0,
      'P': 0.275,
      'C': 0.660
    };
    
    // Calculate the Impact
    const impact = 10.41 * (1 - (1 - impactCoefficients[confidentialityImpact]) * (1 - impactCoefficients[integrityImpact]) * (1 - impactCoefficients[availabilityImpact]));
    
    // Calculate the Exploitability
    const exploitability = 20 * accessVectorCoefficients[accessVector] * accessComplexityCoefficients[accessComplexity] * authenticationCoefficients[authentication];
    
    // Calculate f(Impact)
    const fImpact = (impact === 0) ? 0 : 1.176;
    
    // Calculate the Base Score
    const baseScore = Math.round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact * 10) / 10;
    
    return baseScore;
  }
  
  // Example usage
  const confidentialityImpact = 'C';
  const integrityImpact = 'P';
  const availabilityImpact = 'N';
  const accessVector = 'N';
  const accessComplexity = 'M';
  const authentication = 'S';
  
  const baseScore = calculateCVSS2BaseScore(confidentialityImpact, integrityImpact, availabilityImpact, accessVector, accessComplexity, authentication);
  console.log('CVSS 2.0 Base Score:', baseScore);
  