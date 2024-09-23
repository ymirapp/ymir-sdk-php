<?php

declare(strict_types=1);

/*
 * This file is part of Ymir PHP SDK.
 *
 * (c) Carl Alexander <support@ymirapp.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ymir\Sdk;

use Illuminate\Support\Collection;

/**
 * Interface for the Ymir API client.
 */
interface ClientInterface
{
    /**
     * Add a bastion host to the network.
     */
    public function addBastionHost(int $networkId): Collection;

    /**
     * Add a NAT gateway to the network.
     */
    public function addNatGateway(int $networkId);

    /**
     * Send signal to cancel a deployment.
     */
    public function cancelDeployment(int $deploymentId);

    /**
     * Change the lock of the database server.
     */
    public function changeDatabaseServerLock(int $databaseServerId, bool $locked);

    /**
     * Change the value of the DNS record in the DNS zone.
     */
    public function changeDnsRecord(int $zoneId, string $type, string $name, string $value);

    /**
     * Change the environment variables of the project environment.
     */
    public function changeEnvironmentVariables(int $projectId, string $environment, array $variables, bool $overwrite = false);

    /**
     * Change the value of the project environment secret.
     */
    public function changeSecret(int $projectId, string $environment, string $name, string $value);

    /**
     * Create a new cache on the network.
     */
    public function createCache(int $networkId, string $name, string $type): Collection;

    /**
     * Create a new SSL certificate.
     */
    public function createCertificate(int $providerId, array $domains, string $region): Collection;

    /**
     * Create a new database on the database server.
     */
    public function createDatabase(int $databaseServerId, string $name): Collection;

    /**
     * Create a new database server on the network.
     */
    public function createDatabaseServer(int $networkId, string $name, string $type, ?int $storage = 50, bool $public = false): Collection;

    /**
     * Create a new user on the database server.
     */
    public function createDatabaseUser(int $databaseServerId, string $username, array $databases = []): Collection;

    /**
     * Create a new deployment for a project environment.
     */
    public function createDeployment(int $projectId, string $environment, array $configuration, ?string $assetsHash = null): Collection;

    /**
     * Create a new DNS zone.
     */
    public function createDnsZone(int $providerId, string $name): Collection;

    /**
     * Create a new email identity.
     */
    public function createEmailIdentity(int $providerId, string $name, string $region): Collection;

    /**
     * Create a new project environment.
     */
    public function createEnvironment(int $projectId, string $name): Collection;

    /**
     * Create a new function invocation for a project environment.
     */
    public function createInvocation(int $projectId, string $environment, array $payload): Collection;

    /**
     * Create a new network.
     */
    public function createNetwork(int $providerId, string $name, string $region): Collection;

    /**
     * Create a new project.
     */
    public function createProject(int $providerId, string $name, string $region, array $environments = []): Collection;

    /**
     * Create a new cloud provider.
     */
    public function createProvider(int $teamId, string $name, array $credentials): Collection;

    /**
     * Create a new deployment for redeploying a project environment.
     */
    public function createRedeployment(int $projectId, string $environment): Collection;

    /**
     * Create a new deployment to roll back a project environment.
     */
    public function createRollback(int $projectId, string $environment, int $deploymentId): Collection;

    /**
     * Create a new team.
     */
    public function createTeam(string $name): Collection;

    /**
     * Delete a cache.
     */
    public function deleteCache(int $cacheId);

    /**
     * Delete a SSL certificate.
     */
    public function deleteCertificate(int $certificateId);

    /**
     * Delete a database on a database server.
     */
    public function deleteDatabase(int $databaseServerId, string $name);

    /**
     * Delete a database server.
     */
    public function deleteDatabaseServer(int $databaseServerId);

    /**
     * Delete a database user on a database server.
     */
    public function deleteDatabaseUser(int $databaseServerId, int $userId);

    /**
     * Delete a DNS record.
     */
    public function deleteDnsRecord(int $zoneId, int $recordId);

    /**
     * Delete a DNS zone.
     */
    public function deleteDnsZone(int $zoneId);

    /**
     * Delete an email identity.
     */
    public function deleteEmailIdentity(int $identityId);

    /**
     * Delete a project environment.
     */
    public function deleteEnvironment(int $projectId, string $environment, bool $deleteResources = false);

    /**
     * Delete a network.
     */
    public function deleteNetwork(int $networkId);

    /**
     * Delete a project.
     */
    public function deleteProject(int $projectId, bool $deleteResources = false);

    /**
     * Delete a cloud provider.
     */
    public function deleteProvider(int $providerId);

    /**
     * Delete a secret.
     */
    public function deleteSecret(int $secretId);

    /**
     * Get an access token to authenticate with the Ymir API.
     */
    public function getAccessToken(string $email, string $password, ?string $authenticationCode = null): string;

    /**
     * Get the user's currently active team.
     */
    public function getActiveTeam(): Collection;

    /**
     * Get the upload URL for the artifact file.
     */
    public function getArtifactUploadUrl(int $deploymentId): string;

    /**
     * Get the authenticated user details.
     */
    public function getAuthenticatedUser(): Collection;

    /**
     * Get the bastion host details.
     */
    public function getBastionHost(int $bastionHostId): Collection;

    /**
     * Get the cache details.
     */
    public function getCache(int $cacheId): Collection;

    /**
     * Get the caches that belong to a team.
     */
    public function getCaches(int $teamId): Collection;

    /**
     * Get the available types of cache.
     */
    public function getCacheTypes(int $providerId): Collection;

    /**
     * Get the SSL certificates details.
     */
    public function getCertificate(int $certificateId): Collection;

    /**
     * Get the SSL certificates that belong to a team.
     */
    public function getCertificates(int $teamId): Collection;

    /**
     * Get the list of databases on a database server.
     */
    public function getDatabases(int $databaseServerId): Collection;

    /**
     * Get the database server details.
     */
    public function getDatabaseServer(int $databaseServerId): Collection;

    /**
     * Get the database servers that belong to a team.
     */
    public function getDatabaseServers(int $teamId): Collection;

    /**
     * Get the available types of database server.
     */
    public function getDatabaseServerTypes(int $providerId): Collection;

    /**
     * Get the list of database users on a database server.
     */
    public function getDatabaseUsers(int $databaseServerId): Collection;

    /**
     * Get the deployment details.
     */
    public function getDeployment(int $deploymentId): Collection;

    /**
     * Get the container image used by the deployment.
     */
    public function getDeploymentImage(int $deploymentId): Collection;

    /**
     * Get all the project environment deployments.
     */
    public function getDeployments(int $projectId, string $environment): Collection;

    /**
     * Get the DNS records that belong to a DNS zone.
     */
    public function getDnsRecords(int $zoneId): Collection;

    /**
     * Get the DNS zone details.
     */
    public function getDnsZone(int $zoneId): Collection;

    /**
     * Get the DNS zones that belong to a team.
     */
    public function getDnsZones(int $teamId): Collection;

    /**
     * Get the email identities that belong to a team.
     */
    public function getEmailIdentities(int $teamId): Collection;

    /**
     * Get the email identity details.
     */
    public function getEmailIdentity(int $identityId): Collection;

    /**
     * Get the project environment details.
     */
    public function getEnvironment(int $projectId, string $environment): Collection;

    /**
     * Get the recent logs from a project environment's function.
     */
    public function getEnvironmentLogs(int $projectId, string $environment, string $function, int $since, ?string $order = null): Collection;

    /**
     * Get the project environment's metrics.
     */
    public function getEnvironmentMetrics(int $projectId, string $environment, string $period): Collection;

    /**
     * Get the project's environments.
     */
    public function getEnvironments(int $projectId): Collection;

    /**
     * Get the environment variables of a project environment.
     */
    public function getEnvironmentVariables(int $projectId, string $environment): Collection;

    /**
     * Get the function invocation details.
     */
    public function getInvocation(int $invocationId): Collection;

    /**
     * Get the network details.
     */
    public function getNetwork(int $networkId): Collection;

    /**
     * Get the network that belong to a team.
     */
    public function getNetworks(int $networkId): Collection;

    /**
     * Get the project details.
     */
    public function getProject(int $projectId): Collection;

    /**
     * Get the projects that belong to a team.
     */
    public function getProjects(int $teamId): Collection;

    /**
     * Get the cloud provider details.
     */
    public function getProvider(int $providerId): Collection;

    /**
     * Get the cloud providers that belong to a team.
     */
    public function getProviders(int $teamId): Collection;

    /**
     * Get the list of regions supported by a cloud provider.
     */
    public function getRegions(int $providerId): Collection;

    /**
     * Get all the project environment secrets.
     */
    public function getSecrets(int $projectId, string $environment): Collection;

    /**
     * Get the signed requests for the deployment asset files.
     */
    public function getSignedAssetRequests(int $deploymentId, array $assetFiles): Collection;

    /**
     * Get the signed requests for uploading files to a project environment.
     */
    public function getSignedUploadRequests(int $projectId, string $environment, array $filesToUpload): Collection;

    /**
     * Get the team details.
     */
    public function getTeam($teamId): Collection;

    /**
     * Get the teams that the authenticated user is a member of.
     */
    public function getTeams(): Collection;

    /**
     * Import all the subdomain DNS records into the DNS zone.
     */
    public function importDnsRecords(int $zoneId, array $subdomains = []);

    /**
     * Invalidate paths in the project environment's content delivery network cache.
     */
    public function invalidateCache(int $projectId, string $environment, array $paths);

    /**
     * Remove the bastion host from a network.
     */
    public function removeBastionHost(int $networkId);

    /**
     * Remove the NAT gateway from a network.
     */
    public function removeNatGateway(int $networkId);

    /**
     * Rotate the password of a database server.
     */
    public function rotateDatabaseServerPassword(int $databaseServerId): Collection;

    /**
     * Rotate the password of a database user on a database server.
     */
    public function rotateDatabaseUserPassword(int $databaseServerId, int $userId): Collection;

    /**
     * Set the Ymir API access token.
     */
    public function setAccessToken(string $token);

    /**
     * Send signal to start a deployment.
     */
    public function startDeployment(int $deploymentId);

    /**
     * Update a cache cluster.
     */
    public function updateCache(int $cacheId, string $type);

    /**
     * Update a database server.
     */
    public function updateDatabaseServer(int $databaseServerId, int $storage, string $type);

    /**
     * Update a cloud provider.
     */
    public function updateProvider(int $providerId, array $credentials, string $name);

    /**
     * Validates the project configuration and returns warnings for each environment.
     */
    public function validateProjectConfiguration(int $projectId, array $configuration, array $environments = []): Collection;
}
