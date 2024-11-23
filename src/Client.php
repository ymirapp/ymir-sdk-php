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

use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use GuzzleHttp\Exception\ClientException as GuzzleClientException;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use Illuminate\Support\Collection;
use Psr\Http\Message\ResponseInterface;
use Ymir\Sdk\Exception\ClientException;
use Ymir\Sdk\Exception\UnexpectedApiResponseException;

/**
 * Base implementation of the Ymir API client.
 */
final class Client implements ClientInterface
{
    /**
     * The base URL used to interact with the Ymir API.
     *
     * @var string
     */
    private $baseUrl;

    /**
     * The HTTP client used to interact with the Ymir API.
     *
     * @var GuzzleClientInterface
     */
    private $httpClient;

    /**
     * Ymir API access token.
     *
     * @var string
     */
    private $token;

    /**
     * Constructor.
     */
    public function __construct(GuzzleClientInterface $httpClient, string $baseUrl = 'https://ymirapp.com/api', ?string $token = null)
    {
        $this->baseUrl = rtrim($baseUrl, '/').'/';
        $this->httpClient = $httpClient;
        $this->token = $token;
    }

    /**
     * {@inheritdoc}
     */
    public function addBastionHost(int $networkId): Collection
    {
        return $this->request('post', "/networks/{$networkId}/bastion-host");
    }

    /**
     * {@inheritdoc}
     */
    public function addNatGateway(int $networkId)
    {
        $this->request('post', "/networks/{$networkId}/nat");
    }

    /**
     * {@inheritdoc}
     */
    public function cancelDeployment(int $deploymentId)
    {
        $this->request('post', "/deployments/{$deploymentId}/cancel");
    }

    /**
     * {@inheritdoc}
     */
    public function changeDatabaseServerLock(int $databaseServerId, bool $locked)
    {
        $this->request('post', "/database-servers/{$databaseServerId}/lock", [
            'locked' => $locked,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function changeDnsRecord(int $zoneId, string $type, string $name, string $value)
    {
        $this->request('put', "/zones/{$zoneId}/records", [
            'type' => $type,
            'name' => $name,
            'value' => $value,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function changeEnvironmentVariables(int $projectId, string $environment, array $variables, bool $overwrite = false)
    {
        return $this->request('put', "/projects/{$projectId}/environments/{$environment}/variables", [
            'variables' => $variables,
            'overwrite' => $overwrite,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function changeSecret(int $projectId, string $environment, string $name, string $value)
    {
        return $this->request('put', "/projects/{$projectId}/environments/{$environment}/secrets", [
            'name' => $name,
            'value' => $value,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createCache(int $networkId, string $name, string $type): Collection
    {
        return $this->request('post', "/networks/{$networkId}/caches", [
            'name' => $name,
            'type' => $type,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createCertificate(int $providerId, array $domains, string $region): Collection
    {
        return $this->request('post', "/providers/{$providerId}/certificates", [
            'domains' => $domains,
            'region' => $region,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createDatabase(int $databaseServerId, string $name): Collection
    {
        return $this->request('post', "/database-servers/{$databaseServerId}/databases", [
            'name' => $name,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createDatabaseServer(int $networkId, string $name, string $type, ?int $storage = 50, bool $public = false): Collection
    {
        if ('aurora-mysql' === $type && null !== $storage) {
            throw new \InvalidArgumentException('Cannot specify a "storage" value for "aurora-mysql" database server');
        } elseif ('aurora-mysql' === $type && $public) {
            throw new \InvalidArgumentException('An "aurora-mysql" database server cannot be public');
        }

        $databaseServer = [
            'name' => $name,
            'type' => $type,
        ];

        if ('aurora-mysql' !== $type) {
            $databaseServer['publicly_accessible'] = $public;
            $databaseServer['storage'] = $storage;
        }

        return $this->request('post', "/networks/{$networkId}/database-servers", $databaseServer);
    }

    /**
     * {@inheritdoc}
     */
    public function createDatabaseUser(int $databaseServerId, string $username, array $databases = []): Collection
    {
        return $this->request('post', "/database-servers/{$databaseServerId}/users", [
            'databases' => $databases,
            'username' => $username,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createDeployment(int $projectId, string $environment, array $configuration, ?string $assetsHash = null): Collection
    {
        return $this->request('post', "/projects/{$projectId}/environments/{$environment}/deployments", [
            'assets_hash' => $assetsHash,
            'configuration' => $configuration,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createDnsZone(int $providerId, string $name): Collection
    {
        return $this->request('post', "/providers/{$providerId}/zones", [
            'domain_name' => $name,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createEmailIdentity(int $providerId, string $name, string $region): Collection
    {
        $type = filter_var($name, FILTER_VALIDATE_EMAIL) ? 'email' : 'domain';

        return $this->request('post', "/providers/{$providerId}/email-identities", [
            $type => $name,
            'region' => $region,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createEnvironment(int $projectId, string $name): Collection
    {
        return $this->request('post', "/projects/{$projectId}/environments", [
            'name' => $name,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createInvocation(int $projectId, string $environment, array $payload): Collection
    {
        return $this->request('post', "/projects/{$projectId}/environments/{$environment}/invocations", [
            'payload' => $payload,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createNetwork(int $providerId, string $name, string $region): Collection
    {
        return $this->request('post', "/providers/{$providerId}/networks", [
            'name' => $name,
            'region' => $region,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createProject(int $providerId, string $name, string $region, array $environments = []): Collection
    {
        return $this->request('post', "/providers/{$providerId}/projects", [
            'name' => $name,
            'region' => $region,
            'environments' => $environments,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createProvider(int $teamId, string $name, array $credentials): Collection
    {
        return $this->request('post', "/teams/{$teamId}/providers", [
            'name' => $name,
            'credentials' => $credentials,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createRedeployment(int $projectId, string $environment): Collection
    {
        return $this->request('post', "/projects/{$projectId}/environments/{$environment}/redeployments");
    }

    /**
     * {@inheritdoc}
     */
    public function createRollback(int $projectId, string $environment, int $deploymentId): Collection
    {
        return $this->request('post', "/projects/{$projectId}/environments/{$environment}/rollbacks", [
            'deployment' => $deploymentId,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function createTeam(string $name): Collection
    {
        return $this->request('post', '/teams', [
            'name' => $name,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteCache(int $cacheId)
    {
        $this->request('delete', "/caches/{$cacheId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteCertificate(int $certificateId)
    {
        $this->request('delete', "/certificates/{$certificateId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteDatabase(int $databaseServerId, string $name)
    {
        $this->request('delete', "/database-servers/{$databaseServerId}/databases/{$name}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteDatabaseServer(int $databaseServerId)
    {
        $this->request('delete', "/database-servers/{$databaseServerId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteDatabaseUser(int $databaseServerId, int $userId)
    {
        $this->request('delete', "/database-servers/{$databaseServerId}/users/{$userId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteDnsRecord(int $zoneId, int $recordId)
    {
        $this->request('delete', "/zones/{$zoneId}/records/{$recordId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteDnsZone(int $zoneId)
    {
        $this->request('delete', "/zones/{$zoneId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteEmailIdentity(int $identityId)
    {
        $this->request('delete', "/email-identities/{$identityId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteEnvironment(int $projectId, string $environment, bool $deleteResources = false)
    {
        $this->request('delete', "/projects/{$projectId}/environments/{$environment}", [
            'delete_resources' => $deleteResources,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteNetwork(int $networkId)
    {
        $this->request('delete', "/networks/{$networkId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteProject(int $projectId, bool $deleteResources = false)
    {
        $this->request('delete', "/projects/{$projectId}", [
            'delete_resources' => $deleteResources,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteProvider(int $providerId)
    {
        $this->request('delete', "/providers/{$providerId}");
    }

    /**
     * {@inheritdoc}
     */
    public function deleteSecret(int $secretId)
    {
        $this->request('delete', "/secrets/{$secretId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken(string $email, string $password, ?string $authenticationCode = null): string
    {
        $response = $this->request('post', '/token', [
            'host' => gethostname(),
            'email' => $email,
            'password' => $password,
            'authentication_code' => $authenticationCode,
        ]);

        if (empty($response['access_token'])) {
            throw new UnexpectedApiResponseException('The Ymir API failed to return an access token');
        }

        return $response['access_token'];
    }

    /**
     * {@inheritdoc}
     */
    public function getActiveTeam(): Collection
    {
        return $this->request('get', '/teams/active');
    }

    /**
     * {@inheritdoc}
     */
    public function getArtifactUploadUrl(int $deploymentId): string
    {
        $uploadUrl = (string) $this->request('get', "/deployments/{$deploymentId}/artifact")->get('upload_url');

        if (empty($uploadUrl)) {
            throw new UnexpectedApiResponseException('The Ymir API failed to return the artifact upload URL');
        }

        return $uploadUrl;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthenticatedUser(): Collection
    {
        return $this->request('get', '/user');
    }

    /**
     * {@inheritdoc}
     */
    public function getBastionHost(int $bastionHostId): Collection
    {
        return $this->request('get', "/bastion-hosts/{$bastionHostId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getCache(int $cacheId): Collection
    {
        return $this->request('get', "/caches/{$cacheId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getCaches(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/caches");
    }

    /**
     * {@inheritdoc}
     */
    public function getCacheTypes(int $providerId): Collection
    {
        $types = $this->request('get', "/providers/{$providerId}/caches/types");

        if ($types->isEmpty()) {
            throw new UnexpectedApiResponseException('The Ymir API failed to return the available cache types');
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function getCertificate(int $certificateId): Collection
    {
        return $this->request('get', "/certificates/{$certificateId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getCertificates(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/certificates");
    }

    /**
     * {@inheritdoc}
     */
    public function getDatabases(int $databaseServerId): Collection
    {
        return $this->request('get', "/database-servers/{$databaseServerId}/databases");
    }

    /**
     * {@inheritdoc}
     */
    public function getDatabaseServer(int $databaseServerId): Collection
    {
        return $this->request('get', "/database-servers/{$databaseServerId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getDatabaseServers(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/database-servers");
    }

    /**
     * {@inheritdoc}
     */
    public function getDatabaseServerTypes(int $providerId): Collection
    {
        $types = $this->request('get', "/providers/{$providerId}/database-servers/types");

        if ($types->isEmpty()) {
            throw new UnexpectedApiResponseException('The Ymir API failed to the available types of database servers');
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function getDatabaseUsers(int $databaseServerId): Collection
    {
        return $this->request('get', "/database-servers/{$databaseServerId}/users");
    }

    /**
     * {@inheritdoc}
     */
    public function getDeployment(int $deploymentId): Collection
    {
        return $this->request('get', "/deployments/{$deploymentId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getDeploymentImage(int $deploymentId): Collection
    {
        return $this->request('get', "/deployments/{$deploymentId}/image");
    }

    /**
     * {@inheritdoc}
     */
    public function getDeployments(int $projectId, string $environment): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments/{$environment}/deployments");
    }

    /**
     * {@inheritdoc}
     */
    public function getDnsRecords(int $zoneId): Collection
    {
        return $this->request('get', "/zones/{$zoneId}/records");
    }

    /**
     * {@inheritdoc}
     */
    public function getDnsZone(int $zoneId): Collection
    {
        return $this->request('get', "/zones/{$zoneId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getDnsZones(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/zones");
    }

    /**
     * {@inheritdoc}
     */
    public function getEmailIdentities(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/email-identities");
    }

    /**
     * {@inheritdoc}
     */
    public function getEmailIdentity(int $identityId): Collection
    {
        return $this->request('get', "/email-identities/{$identityId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getEnvironment(int $projectId, string $environment): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments/{$environment}");
    }

    /**
     * {@inheritdoc}
     */
    public function getEnvironmentLogs(int $projectId, string $environment, string $function, int $since, ?string $order = null): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments/{$environment}/logs?".http_build_query([
            'function' => $function,
            'since' => $since,
            'order' => $order,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function getEnvironmentMetrics(int $projectId, string $environment, string $period): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments/{$environment}/metrics?period={$period}");
    }

    /**
     * {@inheritdoc}
     */
    public function getEnvironments(int $projectId): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments");
    }

    /**
     * {@inheritdoc}
     */
    public function getEnvironmentVariables(int $projectId, string $environment): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments/{$environment}/variables");
    }

    /**
     * {@inheritdoc}
     */
    public function getInvocation(int $invocationId): Collection
    {
        return $this->request('get', "/invocations/{$invocationId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getNetwork(int $networkId): Collection
    {
        return $this->request('get', "/networks/{$networkId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getNetworks(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/networks");
    }

    /**
     * {@inheritdoc}
     */
    public function getProject(int $projectId): Collection
    {
        return $this->request('get', "/projects/{$projectId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getProjects(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/projects");
    }

    /**
     * {@inheritdoc}
     */
    public function getProvider(int $providerId): Collection
    {
        return $this->request('get', "/providers/{$providerId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getProviders(int $teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}/providers");
    }

    /**
     * {@inheritdoc}
     */
    public function getRegions(int $providerId): Collection
    {
        return $this->request('get', "/providers/{$providerId}/regions");
    }

    /**
     * {@inheritdoc}
     */
    public function getSecrets(int $projectId, string $environment): Collection
    {
        return $this->request('get', "/projects/{$projectId}/environments/{$environment}/secrets");
    }

    /**
     * {@inheritdoc}
     */
    public function getSignedAssetRequests(int $deploymentId, array $assetFiles): Collection
    {
        $requests = function (array $assets) use ($deploymentId) {
            foreach (array_chunk($assets, 500) as $chunkedAssets) {
                yield $this->createRequest('post', "/deployments/{$deploymentId}/signed-assets", ['assets' => $chunkedAssets]);
            }
        };
        $signedAssetRequests = [];

        $pool = new Pool($this->httpClient, $requests($assetFiles), [
            'concurrency' => 10,
            'fulfilled' => function (ResponseInterface $response) use (&$signedAssetRequests) {
                $signedAssetRequests[] = $this->decodeResponse($response);
            },
            'options' => ['verify' => false],
        ]);
        $pool->promise()->wait();

        $signedAssetRequests = collect($signedAssetRequests)->collapse();

        if (!empty($assetFiles) && $signedAssetRequests->isEmpty()) {
            throw new UnexpectedApiResponseException('The Ymir API failed to return the signed asset requests');
        }

        return $signedAssetRequests;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignedUploadRequests(int $projectId, string $environment, array $filesToUpload): Collection
    {
        $signedUploadRequests = $this->request('post', "/projects/{$projectId}/environments/{$environment}/signed-uploads", ['uploads' => $filesToUpload]);

        if (!empty($filesToUpload) && $signedUploadRequests->isEmpty()) {
            throw new UnexpectedApiResponseException('The Ymir API failed to return the signed upload requests');
        }

        return $signedUploadRequests;
    }

    /**
     * {@inheritdoc}
     */
    public function getTeam($teamId): Collection
    {
        return $this->request('get', "/teams/{$teamId}");
    }

    /**
     * {@inheritdoc}
     */
    public function getTeams(): Collection
    {
        return $this->request('get', '/teams');
    }

    /**
     * {@inheritdoc}
     */
    public function importDnsRecords(int $zoneId, array $subdomains = [])
    {
        $this->request('post', "/zones/{$zoneId}/import-records", [
            'subdomains' => array_filter($subdomains),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function invalidateCache(int $projectId, string $environment, array $paths)
    {
        $this->request('post', "/projects/{$projectId}/environments/{$environment}/invalidate-cache", [
            'paths' => $paths,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function removeBastionHost(int $networkId)
    {
        $this->request('delete', "/networks/{$networkId}/bastion-host");
    }

    /**
     * {@inheritdoc}
     */
    public function removeNatGateway(int $networkId)
    {
        $this->request('delete', "/networks/{$networkId}/nat");
    }

    /**
     * {@inheritdoc}
     */
    public function rotateDatabaseServerPassword(int $databaseServerId): Collection
    {
        return $this->request('post', "/database-servers/{$databaseServerId}/rotate-password");
    }

    /**
     * {@inheritdoc}
     */
    public function rotateDatabaseUserPassword(int $databaseServerId, int $userId): Collection
    {
        return $this->request('post', "/database-servers/{$databaseServerId}/users/{$userId}/rotate-password");
    }

    /**
     * Set the Ymir API access token.
     */
    public function setAccessToken(string $token)
    {
        $this->token = $token;
    }

    /**
     * {@inheritdoc}
     */
    public function startDeployment(int $deploymentId)
    {
        $this->request('post', "/deployments/{$deploymentId}/start");
    }

    /**
     * {@inheritdoc}
     */
    public function updateCache(int $cacheId, string $type)
    {
        $this->request('put', "/caches/{$cacheId}", [
            'type' => $type,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function updateDatabaseServer(int $databaseServerId, int $storage, string $type)
    {
        $this->request('put', "/database-servers/{$databaseServerId}", [
            'storage' => $storage,
            'type' => $type,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function updateProvider(int $providerId, array $credentials, string $name)
    {
        $this->request('put', "/providers/{$providerId}", [
            'name' => $name,
            'credentials' => $credentials,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function validateProjectConfiguration(int $projectId, array $configuration, array $environments = []): Collection
    {
        return $this->request('post', "/projects/{$projectId}/validate-configuration", [
            'configuration' => $configuration,
            'environments' => $environments,
        ]);
    }

    /**
     * Create a PSR request object.
     */
    private function createRequest(string $method, string $uri, array $body = []): Request
    {
        $headers = [
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'User-Agent' => 'ymir-sdk-php/1.2.1',
        ];
        $method = strtolower($method);

        $body = in_array($method, ['delete', 'post', 'put']) ? json_encode($body) : null;

        if (false === $body) {
            throw new \RuntimeException(sprintf('Unable to JSON encode request body: %s', json_last_error_msg()));
        }

        if (!empty($this->token)) {
            $headers['Authorization'] = "Bearer {$this->token}";
        }

        return new Request($method, $this->baseUrl.ltrim($uri, '/'), $headers, $body);
    }

    /**
     * Decode response returned by the Ymir API.
     */
    private function decodeResponse(ResponseInterface $response): Collection
    {
        return collect(json_decode((string) $response->getBody(), true));
    }

    /**
     * Send a request to the Ymir API.
     */
    private function request(string $method, string $uri, array $body = []): Collection
    {
        try {
            $response = $this->httpClient->send($this->createRequest($method, $uri, $body), ['verify' => false]);
        } catch (GuzzleClientException $exception) {
            throw new ClientException($exception);
        }

        return $this->decodeResponse($response);
    }
}
