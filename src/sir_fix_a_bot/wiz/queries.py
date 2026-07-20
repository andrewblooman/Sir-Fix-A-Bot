"""GraphQL documents for the Wiz API.

Wiz's schema evolves; these select a deliberately narrow field set so a schema addition upstream
can't change the shape we parse. If a field here stops resolving, Wiz returns a GraphQL `errors`
array with a 200 status — `client.py` raises on that rather than silently yielding empty findings.
"""

VULNERABILITY_FINDING_BY_ID = """
query VulnerabilityFindingById($filterBy: VulnerabilityFindingFilters, $first: Int!) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first) {
    nodes {
      id
      name
      description
      severity
      score
      fixedVersion
      version
      detailedName
      firstDetectedAt
      vulnerableAsset {
        ... on VulnerableAssetVirtualMachine {
          id
          name
          providerUniqueId
          cloudPlatform
          subscriptionExternalId
          region
        }
        ... on VulnerableAssetContainerImage {
          id
          name
          providerUniqueId
          cloudPlatform
          subscriptionExternalId
          imageId
        }
        ... on VulnerableAssetServerless {
          id
          name
          providerUniqueId
          cloudPlatform
          subscriptionExternalId
          region
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

OPEN_FINDINGS_FOR_SERVICE = """
query OpenFindingsForService(
  $filterBy: VulnerabilityFindingFilters
  $first: Int!
  $after: String
) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      description
      severity
      score
      fixedVersion
      version
      detailedName
      firstDetectedAt
      vulnerableAsset {
        ... on VulnerableAssetContainerImage {
          id
          name
          providerUniqueId
          cloudPlatform
          subscriptionExternalId
          imageId
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""
