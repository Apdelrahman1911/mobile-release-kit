// Shallow constant projection of the two dependency-owned static catalogues.
// Every slice retains the original dependency array address and order.
const fn catalogue_reference(data: &mrk_android_catalogue_schema::CatalogueData) -> Reference {
    Reference {
        profile: data.profile,
        observed_jdk_vendor: data.observed_jdk_vendor,
        observed_jdk_version: data.observed_jdk_version,
        versions: data.versions,
        roles: data.roles,
        gradle_distribution_url: data.gradle_distribution_url,
        gradle_distribution_sha256: data.gradle_distribution_sha256,
        archives: data.archives,
        trees: data.trees,
        source_members: data.source_members,
        source_bindings: data.source_bindings,
        support: data.support,
        support_members: data.support_members,
        payload: data.payload,
        classes: data.classes,
        aliases: data.aliases,
        directories: data.directories,
    }
}
const REFERENCES: &[Reference] = &[catalogue_reference(&mrk_android_catalogue_arm64::CATALOGUE)];
mod intel_catalogue {
    use super::*;
    pub(super) const REFERENCES: &[Reference] = &[catalogue_reference(&mrk_android_catalogue_x86_64::CATALOGUE)];
}
