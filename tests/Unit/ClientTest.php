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

namespace Ymir\Sdk\Tests\Unit;

use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use Illuminate\Support\Arr;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Ymir\Sdk\Client;
use Ymir\Sdk\Exception\UnexpectedApiResponseException;
use Ymir\Sdk\Tests\Mock\FunctionMockTrait;

class ClientTest extends TestCase
{
    use FunctionMockTrait;

    public function testAddBastionHost()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                    ->method('send')
                    ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                        $this->assertSame('POST', $request->getMethod());
                        $this->assertSame("base_url/networks/{$networkId}/bastion-host", (string) $request->getUri());

                        return true;
                    }));

        (new Client($httpClient, 'base_url'))->addBastionHost($networkId);
    }

    public function testAddNatGateway()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}/nat", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->addNatGateway($networkId);
    }

    public function testCancelDeployment()
    {
        $deploymentId = $this->faker->randomDigitNotNull;
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/deployments/{$deploymentId}/cancel", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->cancelDeployment($deploymentId);
    }

    public function testChangeDatabaseServerLockWithLockSetToFalse()
    {
        $databaseServerId = $this->faker->randomDigitNotNull;
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/lock", (string) $request->getUri());
                       $this->assertFalse(Arr::get(json_decode($request->getBody()->getContents(), true), 'locked'));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->changeDatabaseServerLock($databaseServerId, false);
    }

    public function testChangeDatabaseServerLockWithLockSetToTrue()
    {
        $databaseServerId = $this->faker->randomDigitNotNull;
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/lock", (string) $request->getUri());
                       $this->assertTrue(Arr::get(json_decode($request->getBody()->getContents(), true), 'locked'));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->changeDatabaseServerLock($databaseServerId, true);
    }

    public function testChangeDnsRecord()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $zoneId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($zoneId) {
                       $this->assertSame('PUT', $request->getMethod());
                       $this->assertSame("base_url/zones/{$zoneId}/records", (string) $request->getUri());
                       $this->assertEquals(['name' => 'name', 'type' => 'type', 'value' => 'value'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->changeDnsRecord($zoneId, 'type', 'name', 'value');
    }

    public function testChangeEnvironmentVariablesWithOverwriteSetToFalse()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('PUT', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/variables", (string) $request->getUri());
                       $this->assertEquals(['variables' => ['name' => 'value'], 'overwrite' => false], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->changeEnvironmentVariables($projectId, $environment, ['name' => 'value'], false);
    }

    public function testChangeEnvironmentVariablesWithOverwriteSetToTrue()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('PUT', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/variables", (string) $request->getUri());
                       $this->assertEquals(['variables' => ['name' => 'value'], 'overwrite' => true], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->changeEnvironmentVariables($projectId, $environment, ['name' => 'value'], true);
    }

    public function testChangeSecret()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                $this->assertSame('PUT', $request->getMethod());
                $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/secrets", (string) $request->getUri());
                $this->assertEquals(['name' => 'name', 'value' => 'value'], json_decode($request->getBody()->getContents(), true));

                return true;
            }));

        (new Client($httpClient, 'base_url'))->changeSecret($projectId, $environment, 'name', 'value');
    }

    public function testCreateCache()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}/caches", (string) $request->getUri());
                       $this->assertEquals(['name' => 'name', 'engine' => 'engine', 'type' => 'type'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createCache($networkId, 'name', 'engine', 'type');
    }

    public function testCreateCertificate()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                $this->assertSame('POST', $request->getMethod());
                $this->assertSame("base_url/providers/{$providerId}/certificates", (string) $request->getUri());
                $this->assertEquals(['domains' => ['domain'], 'region' => 'region'], json_decode($request->getBody()->getContents(), true));

                return true;
            }));

        (new Client($httpClient, 'base_url'))->createCertificate($providerId, ['domain'], 'region');
    }

    public function testCreateDatabase()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/databases", (string) $request->getUri());
                       $this->assertEquals(['name' => 'database-name'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createDatabase($databaseServerId, 'database-name');
    }

    public function testCreateDatabaseServer()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}/database-servers", (string) $request->getUri());
                       $this->assertEquals(['name' => 'database-server-name', 'type' => 'database-server-type', 'publicly_accessible' => true, 'storage' => 42], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createDatabaseServer($networkId, 'database-server-name', 'database-server-type', 42, true);
    }

    public function testCreateDatabaseServerWithAuroraMySqlAndPubliclyAccessibleSetToTrue()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An "aurora-mysql" database server cannot be public');

        (new Client($this->createMock(GuzzleClientInterface::class), 'base_url'))->createDatabaseServer($this->faker->randomDigitNotNull, 'database-server-name', 'aurora-mysql', null, true);
    }

    public function testCreateDatabaseServerWithAuroraMySqlAndStorageNotNull()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot specify a "storage" value for "aurora-mysql" database server');

        (new Client($this->createMock(GuzzleClientInterface::class), 'base_url'))->createDatabaseServer($this->faker->randomDigitNotNull, 'database-server-name', 'aurora-mysql', 42);
    }

    public function testCreateDatabaseUser()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/users", (string) $request->getUri());
                       $this->assertEquals(['username' => 'database-username', 'databases' => ['database-name']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createDatabaseUser($databaseServerId, 'database-username', ['database-name']);
    }

    public function testCreateDeployment()
    {
        $assetsHash = $this->faker->sha256;
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($assetsHash, $projectId, $environment) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/deployments", (string) $request->getUri());
                       $this->assertEquals(['configuration' => ['configuration'], 'assets_hash' => $assetsHash], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createDeployment($projectId, $environment, ['configuration'], $assetsHash);
    }

    public function testCreateDnsZone()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/zones", (string) $request->getUri());
                       $this->assertEquals(['domain_name' => 'domain'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createDnsZone($providerId, 'domain');
    }

    public function testCreateEmailIdentityWithDomainName()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $identity = $this->faker->domainName;
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($identity, $providerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/email-identities", (string) $request->getUri());
                       $this->assertEquals(['domain' => $identity, 'region' => 'region'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createEmailIdentity($providerId, $identity, 'region');
    }

    public function testCreateEmailIdentityWithEmailAddress()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $identity = $this->faker->email;
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($identity, $providerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/email-identities", (string) $request->getUri());
                       $this->assertEquals(['email' => $identity, 'region' => 'region'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createEmailIdentity($providerId, $identity, 'region');
    }

    public function testCreateEnvironment()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments", (string) $request->getUri());
                       $this->assertEquals(['name' => 'environment-name'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createEnvironment($projectId, 'environment-name');
    }

    public function testCreateInvocation()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;
        $environment = $this->faker->slug;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId, $environment) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/invocations", (string) $request->getUri());
                       $this->assertEquals(['payload' => ['payload']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createInvocation($projectId, $environment, ['payload']);
    }

    public function testCreateNetwork()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/networks", (string) $request->getUri());
                       $this->assertEquals(['name' => 'network-name', 'region' => 'region'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createNetwork($providerId, 'network-name', 'region');
    }

    public function testCreateProject()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/projects", (string) $request->getUri());
                       $this->assertEquals(['name' => 'project-name', 'region' => 'region', 'environments' => []], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createProject($providerId, 'project-name', 'region');
    }

    public function testCreateProvider()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/providers", (string) $request->getUri());
                       $this->assertEquals(['name' => 'provider-name', 'credentials' => ['credentials']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createProvider($teamId, 'provider-name', ['credentials']);
    }

    public function testCreateRedeployment()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;
        $environment = $this->faker->slug;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId, $environment) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/redeployments", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createRedeployment($projectId, $environment);
    }

    public function testCreateRollback()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $deploymentId = $this->faker->randomDigitNotNull;
        $projectId = $this->faker->randomDigitNotNull;
        $environment = $this->faker->slug;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId, $projectId, $environment) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/rollbacks", (string) $request->getUri());
                       $this->assertEquals(['deployment' => $deploymentId], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createRollback($projectId, $environment, $deploymentId);
    }

    public function testCreateTeam()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame('base_url/teams', (string) $request->getUri());
                       $this->assertEquals(['name' => 'team-name'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->createTeam('team-name');
    }

    public function testDeleteCache()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $cacheId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($cacheId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/caches/{$cacheId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteCache($cacheId);
    }

    public function testDeleteCertificate()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $certificateId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($certificateId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/certificates/{$certificateId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteCertificate($certificateId);
    }

    public function testDeleteDatabase()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;
        $databaseName = $this->faker->slug;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseName, $databaseServerId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/databases/{$databaseName}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteDatabase($databaseServerId, $databaseName);
    }

    public function testDeleteDatabaseServer()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteDatabaseServer($databaseServerId);
    }

    public function testDeleteDatabaseUser()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;
        $databaseUserId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId, $databaseUserId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/users/{$databaseUserId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteDatabaseUser($databaseServerId, $databaseUserId);
    }

    public function testDeleteDnsRecord()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $dnsRecordId = $this->faker->randomDigitNotNull;
        $zoneId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($dnsRecordId, $zoneId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/zones/{$zoneId}/records/{$dnsRecordId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteDnsRecord($zoneId, $dnsRecordId);
    }

    public function testDeleteDnsZone()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $zoneId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($zoneId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/zones/{$zoneId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteDnsZone($zoneId);
    }

    public function testDeleteEmailIdentity()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $emailIdentityId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($emailIdentityId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/email-identities/{$emailIdentityId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteEmailIdentity($emailIdentityId);
    }

    public function testDeleteEnvironmentWithDeleteResourcesSetToFalse()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;
        $environment = $this->faker->slug;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId, $environment) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}", (string) $request->getUri());
                       $this->assertEquals(['delete_resources' => false], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteEnvironment($projectId, $environment, false);
    }

    public function testDeleteEnvironmentWithDeleteResourcesSetToTrue()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;
        $environment = $this->faker->slug;

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) use ($projectId, $environment) {
                $this->assertSame('DELETE', $request->getMethod());
                $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}", (string) $request->getUri());
                $this->assertEquals(['delete_resources' => true], json_decode($request->getBody()->getContents(), true));

                return true;
            }));

        (new Client($httpClient, 'base_url'))->deleteEnvironment($projectId, $environment, true);
    }

    public function testDeleteNetwork()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteNetwork($networkId);
    }

    public function testDeleteProjectWithDeleteResourcesSetToFalse()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}", (string) $request->getUri());
                       $this->assertEquals(['delete_resources' => false], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteProject($projectId, false);
    }

    public function testDeleteProjectWithDeleteResourcesSetToTrue()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}", (string) $request->getUri());
                       $this->assertEquals(['delete_resources' => true], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteProject($projectId, true);
    }

    public function testDeleteProvider()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteProvider($providerId);
    }

    public function testDeleteSecret()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $secretId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($secretId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/secrets/{$secretId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->deleteSecret($secretId);
    }

    public function testGetAccessTokenReturnsAccessTokenWithAuthenticationCode()
    {
        $gethostname = $this->getFunctionMock($this->getNamespace(Client::class), 'gethostname');
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $gethostname->expects($this->once())
            ->willReturn('hostname');

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) {
                $this->assertSame('POST', $request->getMethod());
                $this->assertSame('base_url/token', (string) $request->getUri());
                $this->assertEquals(['host' => 'hostname', 'email' => 'email', 'password' => 'password', 'authentication_code' => 'code'], json_decode($request->getBody()->getContents(), true));

                return true;
            }))
            ->willReturn($response);

        $response->expects($this->once())
            ->method('getBody')
            ->willReturn(json_encode(['access_token' => 'access_token']));

        $this->assertSame('access_token', (new Client($httpClient, 'base_url'))->getAccessToken('email', 'password', 'code'));
    }

    public function testGetAccessTokenReturnsAccessTokenWithoutAuthenticationCode()
    {
        $gethostname = $this->getFunctionMock($this->getNamespace(Client::class), 'gethostname');
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $gethostname->expects($this->once())
                    ->willReturn('hostname');

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame('base_url/token', (string) $request->getUri());
                       $this->assertEquals(['host' => 'hostname', 'email' => 'email', 'password' => 'password', 'authentication_code' => null], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }))
                   ->willReturn($response);

        $response->expects($this->once())
                 ->method('getBody')
                 ->willReturn(json_encode(['access_token' => 'access_token']));

        $this->assertSame('access_token', (new Client($httpClient, 'base_url'))->getAccessToken('email', 'password'));
    }

    public function testGetAccessTokenWithMissingAccessCode()
    {
        $this->expectException(UnexpectedApiResponseException::class);
        $this->expectExceptionMessage('The Ymir API failed to return an access token');

        $gethostname = $this->getFunctionMock($this->getNamespace(Client::class), 'gethostname');
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $gethostname->expects($this->once())
                    ->willReturn('hostname');

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame('base_url/token', (string) $request->getUri());
                       $this->assertEquals(['host' => 'hostname', 'email' => 'email', 'password' => 'password', 'authentication_code' => 'code'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getAccessToken('email', 'password', 'code');
    }

    public function testGetActiveTeam()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame('base_url/teams/active', (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getActiveTeam();
    }

    public function testGetArtifactUploadUrlReturnsUploadUrl()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $deploymentId = $this->faker->randomDigitNotNull;
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/deployments/{$deploymentId}/artifact", (string) $request->getUri());

                       return true;
                   }))
                   ->willReturn($response);

        $response->expects($this->once())
                 ->method('getBody')
                 ->willReturn(json_encode(['upload_url' => 'upload_url']));

        $this->assertSame('upload_url', (new Client($httpClient, 'base_url'))->getArtifactUploadUrl($deploymentId));
    }

    public function testGetArtifactUploadUrlWithMissingUploadUrl()
    {
        $this->expectException(UnexpectedApiResponseException::class);
        $this->expectExceptionMessage('The Ymir API failed to return the artifact upload URL');

        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $deploymentId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/deployments/{$deploymentId}/artifact", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getArtifactUploadUrl($deploymentId);
    }

    public function testGetAuthenticatedUser()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame('base_url/user', (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getAuthenticatedUser();
    }

    public function testGetBastionHost()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $bastionHostId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($bastionHostId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/bastion-hosts/{$bastionHostId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getBastionHost($bastionHostId);
    }

    public function testGetCache()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $cacheId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($cacheId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/caches/{$cacheId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getCache($cacheId);
    }

    public function testGetCaches()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/caches", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getCaches($teamId);
    }

    public function testGetCacheTypesReturnsCacheTypes()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/caches/types", (string) $request->getUri());

                       return true;
                   }))
                   ->willReturn($response);

        $response->expects($this->once())
                 ->method('getBody')
                 ->willReturn(json_encode(['cache_type']));

        $this->assertSame(['cache_type'], (new Client($httpClient, 'base_url'))->getCacheTypes($providerId)->all());
    }

    public function testGetCacheTypesReturnsEmptyCacheTypes()
    {
        $this->expectException(UnexpectedApiResponseException::class);
        $this->expectExceptionMessage('The Ymir API failed to return the available cache types');

        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;
        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/caches/types", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getCacheTypes($providerId);
    }

    public function testGetCertificate()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $certificateId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($certificateId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/certificates/{$certificateId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getCertificate($certificateId);
    }

    public function testGetCertificates()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/certificates", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getCertificates($teamId);
    }

    public function testGetDatabases()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/databases", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDatabases($databaseServerId);
    }

    public function testGetDatabaseServer()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDatabaseServer($databaseServerId);
    }

    public function testGetDatabaseServers()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/database-servers", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDatabaseServers($teamId);
    }

    public function testGetDatabaseServerTypesReturnsDatabaseServerTypes()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/database-servers/types", (string) $request->getUri());

                       return true;
                   }))
                   ->willReturn($response);

        $response->expects($this->once())
                 ->method('getBody')
                 ->willReturn(json_encode(['database_server_type']));

        $this->assertSame(['database_server_type'], (new Client($httpClient, 'base_url'))->getDatabaseServerTypes($providerId)->all());
    }

    public function testGetDatabaseServerTypesReturnsEmptyDatabaseServerTypes()
    {
        $this->expectException(UnexpectedApiResponseException::class);
        $this->expectExceptionMessage('The Ymir API failed to the available types of database servers');

        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;
        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/database-servers/types", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDatabaseServerTypes($providerId);
    }

    public function testGetDatabaseUsers()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/users", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDatabaseUsers($databaseServerId);
    }

    public function testGetDeployment()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $deploymentId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/deployments/{$deploymentId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDeployment($deploymentId);
    }

    public function testGetDeploymentImage()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $deploymentId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/deployments/{$deploymentId}/image", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDeploymentImage($deploymentId);
    }

    public function testGetDnsRecords()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $zoneId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($zoneId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/zones/{$zoneId}/records", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDnsRecords($zoneId);
    }

    public function testGetDnsZone()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $zoneId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($zoneId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/zones/{$zoneId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDnsZone($zoneId);
    }

    public function testGetDnsZones()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/zones", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getDnsZones($teamId);
    }

    public function testGetEmailIdentities()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/email-identities", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getEmailIdentities($teamId);
    }

    public function testGetEmailIdentity()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $identityId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($identityId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/email-identities/{$identityId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getEmailIdentity($identityId);
    }

    public function testGetEnvironment()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getEnvironment($projectId, $environment);
    }

    public function testGetEnvironmentLogsWithOrder()
    {
        $environment = $this->faker->slug;
        $function = $this->faker->slug;
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $order = 'desc';
        $projectId = $this->faker->randomDigitNotNull;
        $since = $this->faker->numberBetween();

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) use ($environment, $function, $order, $projectId, $since) {
                $this->assertSame('GET', $request->getMethod());
                $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/logs?function={$function}&since={$since}&order={$order}", (string) $request->getUri());

                return true;
            }));

        (new Client($httpClient, 'base_url'))->getEnvironmentLogs($projectId, $environment, $function, $since, $order);
    }

    public function testGetEnvironmentLogsWithoutOrder()
    {
        $environment = $this->faker->slug;
        $function = $this->faker->slug;
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;
        $since = $this->faker->numberBetween();

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) use ($environment, $function, $projectId, $since) {
                $this->assertSame('GET', $request->getMethod());
                $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/logs?function={$function}&since={$since}", (string) $request->getUri());

                return true;
            }));

        (new Client($httpClient, 'base_url'))->getEnvironmentLogs($projectId, $environment, $function, $since);
    }

    public function testGetEnvironmentMetrics()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/metrics?period=7d", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getEnvironmentMetrics($projectId, $environment, '7d');
    }

    public function testGetEnvironments()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getEnvironments($projectId);
    }

    public function testGetEnvironmentVariables()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/variables", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getEnvironmentVariables($projectId, $environment);
    }

    public function testGetInvocation()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $invocationId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($invocationId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/invocations/{$invocationId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getInvocation($invocationId);
    }

    public function testGetNetwork()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getNetwork($networkId);
    }

    public function testGetNetworks()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/networks", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getNetworks($teamId);
    }

    public function testGetProject()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getProject($projectId);
    }

    public function testGetProjects()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/projects", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getProjects($teamId);
    }

    public function testGetProvider()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getProvider($providerId);
    }

    public function testGetProviders()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}/providers", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getProviders($teamId);
    }

    public function testGetRegions()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}/regions", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getRegions($providerId);
    }

    public function testGetSecrets()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/secrets", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getSecrets($projectId, $environment);
    }

    public function testGetSignedUploadRequestsReturnsNoSignedUploadRequests()
    {
        $this->expectException(UnexpectedApiResponseException::class);
        $this->expectExceptionMessage('The Ymir API failed to return the signed upload requests');

        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/signed-uploads", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getSignedUploadRequests($projectId, $environment, ['uploads_file'])->all();
    }

    public function testGetSignedUploadRequestsReturnsSignedUploadRequests()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;
        $response = $this->createMock(ResponseInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/signed-uploads", (string) $request->getUri());
                       $this->assertEquals(['uploads' => ['uploads_file']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }))
                   ->willReturn($response);

        $response->expects($this->once())
                 ->method('getBody')
                 ->willReturn(json_encode(['signed_upload_request']));

        $this->assertSame(['signed_upload_request'], (new Client($httpClient, 'base_url'))->getSignedUploadRequests($projectId, $environment, ['uploads_file'])->all());
    }

    public function testGetTeam()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $teamId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($teamId) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame("base_url/teams/{$teamId}", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getTeam($teamId);
    }

    public function testGetTeams()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) {
                       $this->assertSame('GET', $request->getMethod());
                       $this->assertSame('base_url/teams', (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->getTeams();
    }

    public function testImportDnsRecords()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $zoneId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($zoneId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/zones/{$zoneId}/import-records", (string) $request->getUri());
                       $this->assertEquals(['subdomains' => ['subdomain']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->importDnsRecords($zoneId, ['subdomain']);
    }

    public function testInvalidateCache()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $environment = $this->faker->slug;
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($environment, $projectId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/environments/{$environment}/invalidate-cache", (string) $request->getUri());
                       $this->assertEquals(['paths' => ['path']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->invalidateCache($projectId, $environment, ['path']);
    }

    public function testRemoveBastionHost()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}/bastion-host", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->removeBastionHost($networkId);
    }

    public function testRemoveNatGateway()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $networkId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($networkId) {
                       $this->assertSame('DELETE', $request->getMethod());
                       $this->assertSame("base_url/networks/{$networkId}/nat", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->removeNatGateway($networkId);
    }

    public function testRotateDatabaseServerPassword()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/rotate-password", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->rotateDatabaseServerPassword($databaseServerId);
    }

    public function testRotateDatabaseUserPassword()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;
        $databaseUserId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId, $databaseUserId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}/users/{$databaseUserId}/rotate-password", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->rotateDatabaseUserPassword($databaseServerId, $databaseUserId);
    }

    public function testStartDeployment()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $deploymentId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($deploymentId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/deployments/{$deploymentId}/start", (string) $request->getUri());

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->startDeployment($deploymentId);
    }

    public function testUpdateCache()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $cacheId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
            ->method('send')
            ->with($this->callback(function (RequestInterface $request) use ($cacheId) {
                $this->assertSame('PUT', $request->getMethod());
                $this->assertSame("base_url/caches/{$cacheId}", (string) $request->getUri());
                $this->assertEquals(['type' => 'cache-type'], json_decode($request->getBody()->getContents(), true));

                return true;
            }));

        (new Client($httpClient, 'base_url'))->updateCache($cacheId, 'cache-type');
    }

    public function testUpdateDatabaseServer()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $databaseServerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($databaseServerId) {
                       $this->assertSame('PUT', $request->getMethod());
                       $this->assertSame("base_url/database-servers/{$databaseServerId}", (string) $request->getUri());
                       $this->assertEquals(['storage' => 42, 'type' => 'database-server-type'], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->updateDatabaseServer($databaseServerId, 42, 'database-server-type');
    }

    public function testUpdateProvider()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $providerId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($providerId) {
                       $this->assertSame('PUT', $request->getMethod());
                       $this->assertSame("base_url/providers/{$providerId}", (string) $request->getUri());
                       $this->assertEquals(['name' => 'provider-name', 'credentials' => ['credential']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->updateProvider($providerId, ['credential'], 'provider-name');
    }

    public function testValidateProjectConfiguration()
    {
        $httpClient = $this->createMock(GuzzleClientInterface::class);
        $projectId = $this->faker->randomDigitNotNull;

        $httpClient->expects($this->once())
                   ->method('send')
                   ->with($this->callback(function (RequestInterface $request) use ($projectId) {
                       $this->assertSame('POST', $request->getMethod());
                       $this->assertSame("base_url/projects/{$projectId}/validate-configuration", (string) $request->getUri());
                       $this->assertEquals(['configuration' => ['configuration'], 'environments' => ['environment']], json_decode($request->getBody()->getContents(), true));

                       return true;
                   }));

        (new Client($httpClient, 'base_url'))->validateProjectConfiguration($projectId, ['configuration'], ['environment']);
    }
}
