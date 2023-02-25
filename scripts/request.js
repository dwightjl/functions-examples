const ethers = require('ethers')
const ethcrypto = require('eth-crypto')
const axios = require('axios')
const fs = require('fs').promises
const dotenv = require('dotenv').config()
const prompt = require('prompt-sync')()


async function main() {

    // Provider config currently set for Polygon Mumbai
    // Optionally use one of the other ethers providers
    // https://docs.ethers.org/v6/api/providers/
    const provider = new ethers.JsonRpcProvider(process.env.MUMBAI_RPC_URL)

    // Oracle config
    // Set for the oracle contract on Polygon Mumbai
    // 0xeA6721aC65BCeD841B8ec3fc5fEdeA6141a0aDE4
    const oracleFactoryAddress = '0xeA6721aC65BCeD841B8ec3fc5fEdeA6141a0aDE4'
    const oracleAbiPath = './artifacts/contracts/dev/functions/FunctionsOracle.sol/FunctionsOracle.json'

    // Consumer details
    const consumerAddress = 'your-deployed-functions-consumer-address'
    const consumerAbiPath = './artifacts/contracts/FunctionsConsumer.sol/FunctionsConsumer.json'
    const subId = 18 // Chainlink Functions subscription ID
    const gasLimit = 250000 // Transaction gas limit
    const verificationBlocks = 2 // Number of blocks to wait for transaction

    // Gas limit for the Chainlink Functions request
    const requestgas = 5500000

    // Get the source to run on the DON
    // Can optionally be a string
    functionSource = await fs.readFile('./examples/Functions-request-source.js', 'utf8')

    // Request config
    const requestConfig = {
        // location of source code. Only 0 (inline) is currently supported
        codeLocation: 0,
        // location of secrets (Inline 0 or Remote 1)
        secretsLocation: 0,
        // string containing the source code to be executed
        source: functionSource,
        // args can be accessed within the source code with `args[index]` (ie: args[0])
        args: ["ETH", "USD"],

        //Optional request config params
        //An array of redundant URLs that point to encrypted off-chain secrets
        //secretsURLs: ['https://gist.github.com/your_github_id/gist_hash/raw/'],
        //Secrets to be encrypted and transmitted inline
        secrets: { apiKey: '' },
        //secrets: { apiKey: process.env.COINMARKETCAP_API_KEY },
        //Default offchain secrets object used by the `functions-build-offchain-secrets` command
        //globalOffchainSecrets: { apiKey: process.env.COINMARKETCAP_API_KEY },
        //Per-node offchain secrets objects used by the `functions-build-offchain-secrets` command
        //perNodeOffchainSecrets: [],
      }

    // Get private wallet key from the .env file
    const signerPrivateKey = process.env.PRIVATE_KEY
    const signer = new ethers.Wallet(signerPrivateKey, provider);

    // Create consumer contract object from consumerAbiPath
    const contractAbi = JSON.parse(await fs.readFile(
        consumerAbiPath,
        'utf8'
        )).abi

    const consumerContract = new ethers.Contract(
      consumerAddress,
      contractAbi,
      signer
      )

    // Create oracle contract object from oracleAbiPath
    const oracleAbi = JSON.parse(await fs.readFile(
        oracleAbiPath,
        'utf8'
        )).abi

    const oracleContract = new ethers.Contract(
      oracleFactoryAddress,
      oracleAbi,
      signer
      )
    
    // Encrypt secrets
    encryptedSecrets = await getEncryptedSecrets(
      requestConfig,
      oracleContract,
      signerPrivateKey
      )


    // Confirm request
    console.log('Request generated without errors')
    var proceed = prompt('Send request? (y/N) ')
    if (proceed != 'y' && proceed != 'Y') {
      console.log('Exiting without sending a request.')
      process.exit(0)
    }

    // Submit the request
    // Order of the parameters is critical
    const requestTx = await consumerContract.executeRequest(
        requestConfig.source,
        encryptedSecrets ?? [], // encryptWithSignature() or encrypt()
        requestConfig.secretsLocation, // 1 for off-chain, 0 for inline
        requestConfig.args ?? [], // Chainlink Functions request args
        subId, // Subscription ID
        gasLimit, // Gas limit for the transaction
        overrides = {
          //Gas limit for the Chainlink Functions request
          gasLimit: requestgas
        }
      )

    // If a response is not received within 5 minutes, the request has failed
    setTimeout(
        () =>
            reject(
                'A response not received within 5 minutes of the request ' +
                'being initiated and has been canceled. Your subscription ' +
                'was not charged. Please make a new request.'
            ),
        300_000
    )
    console.log(
      `Waiting ${verificationBlocks} blocks for transaction ` +
      `${requestTx.hash} to be confirmed...`
    )

    // TODO: Need a better way to print this. Works on some requests and not others
    const requestTxReceipt = await requestTx.wait(verificationBlocks)
    if(requestTxReceipt.logs[2].args.id){
      requestId = requestTxReceipt.logs[2].args.id
      console.log(`\nRequest ${requestId} initiated`)
    }

    console.log(`Waiting for fulfillment...\n`)

    // TODO: Detect when the fulfillment is done rather than pausing
    await new Promise(r => setTimeout(r, 30000))

    // Check for errors
    let latestError = await consumerContract.latestError()
    if (latestError.length > 0 && latestError !== "0x") {
      const errorString = Buffer.from(latestError.slice(2), "hex").toString()
      console.log(`\nOn-chain error message: ${Buffer.from(latestError.slice(2), "hex").toString()}`)
    }

    // Decode and print the latest response
    let latestResponse = await consumerContract.latestResponse()
    if (latestResponse.length > 0 && latestResponse !== "0x") {
      latestResponse = BigInt(await latestResponse).toString()
      console.log('Stored value is: ' + latestResponse)
    }


}

// Encrypt the secrets as defined in requestConfig
// The code is a modified version of buildRequest.js from the starter kit:
// ./FunctionsSandboxLibrary/buildRequest.js
// Expects one of the following:
//   - A JSON object with { apiKey: 'your_secret_here' }
//   - An array of secretsURLs and globalOffchainSecrets
async function getEncryptedSecrets(requestConfig, oracle, signerPrivateKey){

    // Fetch the DON public key from on-chain
    const DONPublicKey = await oracle.getDONPublicKey()
    // Remove the preceding 0x from the DON public key
    requestConfig.DONPublicKey = DONPublicKey.slice(2)

    if (requestConfig.secretsLocation === 1) {
        if (!requestConfig.globalOffchainSecrets || Object.keys(requestConfig.globalOffchainSecrets).length === 0) {
            if (
                requestConfig.perNodeOffchainSecrets &&
                requestConfig.perNodeOffchainSecrets[0] &&
                Object.keys(requestConfig.perNodeOffchainSecrets[0]).length > 0
            ) {
                requestConfig.secrets = requestConfig.perNodeOffchainSecrets[0]
            }
        } else {
            requestConfig.secrets = requestConfig.globalOffchainSecrets
        }
        // Get node addresses for off-chain secrets
        const [nodeAddresses] = await oracle.getAllNodePublicKeys()
        if (requestConfig.secretsURLs && requestConfig.secretsURLs.length > 0) {
            await verifyOffchainSecrets(requestConfig.secretsURLs, nodeAddresses)
        }
    }

    if (requestConfig.secrets) {
        if (!requestConfig.DONPublicKey) {
          throw Error('DONPublicKey not in config')
        }
        if (requestConfig.secretsLocation === 0) {
          if (typeof requestConfig.secrets !== 'object') {
            throw Error('Unsupported inline secrets format. Inline secrets must be an object')
          }
          // If the secrets object is empty, do nothing, else encrypt secrets
          if (Object.keys(requestConfig.secrets).length !== 0) {
            requestConfig.secrets =
              '0x' +
              (await (0, encryptWithSignature)(
                signerPrivateKey,
                requestConfig.DONPublicKey,
                JSON.stringify(requestConfig.secrets)
              ))
          }
        }
        if (requestConfig.secretsLocation === 1) {
          if (!Array.isArray(requestConfig.secretsURLs)) {
            throw Error('Unsupported remote secrets format.  Remote secrets must be an array.')
          }
          // If the secrets URLs is empty, do nothing, else encrypt secrets URLs
          if (requestConfig.secretsURLs.length > 0) {
            requestConfig.secrets =
              '0x' + (await (0, encrypt)(requestConfig.DONPublicKey, requestConfig.secretsURLs.join(' ')))
          }
        }
      }


    // End replacing buildRequest()
    return requestConfig.secrets
}

// Check each URL in secretsURLs to make sure it is available
// Code is from ./tasks/Functions-client/buildRequestJSON.js
// in the starter kit.
async function verifyOffchainSecrets (secretsURLs, nodeAddresses) {
    const offchainSecretsResponses = []
    for (const url of secretsURLs) {
      try {
        const response = await axios.request({
          url,
          timeout: 3000,
          responseType: 'json',
          maxContentLength: 1000000,
        })
        offchainSecretsResponses.push({
          url,
          secrets: response.data,
        })
      } catch (error) {
        throw Error(`Failed to fetch off-chain secrets from ${url}\n${error}`)
      }
    }
  
    for (const { secrets, url } of offchainSecretsResponses) {
      if (JSON.stringify(secrets) !== JSON.stringify(offchainSecretsResponses[0].secrets)) {
        throw Error(
          `Off-chain secrets URLs ${url} and ${offchainSecretsResponses[0].url} do not contain the same JSON object.  All secrets URLs must have an identical JSON object.`
        )
      }
  
      for (const nodeAddress of nodeAddresses) {
        if (!secrets[nodeAddress.toLowerCase()]) {
          if (!secrets['0x0']) {
            throw Error(`No secrets specified for node ${nodeAddress.toLowerCase()} and no default secrets found.`)
          }
          console.log(
            `WARNING: No secrets found for node ${nodeAddress.toLowerCase()}.  That node will use default secrets specified by the "0x0" entry.`
          )
        }
      }
    }
}

// Encrypt with the signer private key for sending secrets through an on-chain contract
// Code is from ./FunctionsSandboxLibrary/encryptSecrets.js
async function encryptWithSignature(signerPrivateKey, readerPublicKey, message) {
  const signature = ethcrypto.default.sign(signerPrivateKey, ethcrypto.default.hash.keccak256(message))
  const payload = {
    message,
    signature,
  }
  return await (0, encrypt)(readerPublicKey, JSON.stringify(payload))
}

// Encrypt with the DON public key
// Code is from ./FunctionsSandboxLibrary/encryptSecrets.js
async function encrypt(readerPublicKey, message) {
  const encrypted = await ethcrypto.default.encryptWithPublicKey(readerPublicKey, message)
  return ethcrypto.default.cipher.stringify(encrypted)
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });