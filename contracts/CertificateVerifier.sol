// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CertificateVerifier
 * @author AuthScan Blockchain
 * @notice A smart contract for issuing, verifying, and managing digital certificates on the blockchain
 * @dev This contract allows authorized issuers to create certificates, verify their authenticity,
 *      and revoke them when necessary. All operations are tracked on-chain for transparency.
 */
contract CertificateVerifier {
    /**
     * @notice Structure to store certificate information
     * @param certificateHash Unique hash identifier for the certificate (typically SHA-256)
     * @param issuer Address of the entity that issued the certificate
     * @param timestamp Block timestamp when the certificate was issued
     * @param isRevoked Boolean flag indicating if the certificate has been revoked
     * @param metadata Additional metadata associated with the certificate (JSON string or other format)
     */
    struct Certificate {
        string certificateHash;
        address issuer;
        uint256 timestamp;
        bool isRevoked;
        string metadata;
    }
    
    /**
     * @notice Mapping from certificate hash to Certificate struct
     * @dev Public mapping allows direct access to certificate data
     */
    mapping(string => Certificate) public certificates;
    
    /**
     * @notice Mapping to track which addresses are authorized to issue certificates
     * @dev Only addresses set to true can issue new certificates
     */
    mapping(address => bool) public authorizedIssuers;
    
    /**
     * @notice Mapping to quickly check if a certificate hash exists
     * @dev Used for efficient existence checks without loading the full Certificate struct
     */
    mapping(string => bool) public certificateExists;
    
    /**
     * @notice Address of the contract owner
     * @dev Owner has special privileges like authorizing/deauthorizing issuers
     */
    address public owner;
    
    /**
     * @notice Total count of certificates issued
     * @dev Useful for statistics and tracking contract usage
     */
    uint256 public totalCertificates;
    
    /**
     * @notice Event emitted when a new certificate is issued
     * @param certificateHash The hash of the issued certificate
     * @param issuer The address that issued the certificate
     * @param timestamp The block timestamp when the certificate was issued
     */
    event CertificateIssued(
        string indexed certificateHash,
        address indexed issuer,
        uint256 timestamp
    );
    
    /**
     * @notice Event emitted when a certificate is revoked
     * @param certificateHash The hash of the revoked certificate
     * @param issuer The address that revoked the certificate (could be original issuer or owner)
     */
    event CertificateRevoked(
        string indexed certificateHash,
        address indexed issuer
    );
    
    /**
     * @notice Event emitted when a new issuer is authorized
     * @param issuer The address that was authorized
     * @param authorizedBy The address that authorized the issuer (typically the owner)
     */
    event IssuerAuthorized(
        address indexed issuer,
        address indexed authorizedBy
    );
    
    /**
     * @notice Event emitted when an issuer is deauthorized
     * @param issuer The address that was deauthorized
     * @param deauthorizedBy The address that deauthorized the issuer (typically the owner)
     */
    event IssuerDeauthorized(
        address indexed issuer,
        address indexed deauthorizedBy
    );
    
    /**
     * @notice Event emitted when ownership is transferred
     * @param previousOwner The address of the previous owner
     * @param newOwner The address of the new owner
     */
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    /**
     * @notice Modifier to restrict function access to the contract owner only
     * @dev Reverts the transaction if the caller is not the owner
     */
    modifier onlyOwner() {
        require(msg.sender == owner, "CertificateVerifier: caller is not the owner");
        _;
    }
    
    /**
     * @notice Modifier to restrict function access to authorized issuers only
     * @dev Reverts the transaction if the caller is not an authorized issuer
     */
    modifier onlyAuthorizedIssuer() {
        require(
            authorizedIssuers[msg.sender],
            "CertificateVerifier: caller is not an authorized issuer"
        );
        _;
    }
    
    /**
     * @notice Modifier to validate that an address is not the zero address
     * @param _address The address to validate
     */
    modifier validAddress(address _address) {
        require(_address != address(0), "CertificateVerifier: zero address not allowed");
        _;
    }
    
    /**
     * @notice Constructor initializes the contract with the deployer as owner and first authorized issuer
     * @dev The contract deployer automatically becomes the owner and first authorized issuer
     */
    constructor() {
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true;
        totalCertificates = 0;
        
        emit IssuerAuthorized(msg.sender, msg.sender);
    }
    
    /**
     * @notice Authorizes a new address to issue certificates
     * @dev Only the owner can authorize new issuers. The address must not be zero.
     * @param issuer The address to authorize as an issuer
     */
    function authorizeIssuer(address issuer) external onlyOwner validAddress(issuer) {
        require(
            !authorizedIssuers[issuer],
            "CertificateVerifier: issuer is already authorized"
        );
        
        authorizedIssuers[issuer] = true;
        emit IssuerAuthorized(issuer, msg.sender);
    }
    
    /**
     * @notice Removes authorization from an issuer
     * @dev Only the owner can deauthorize issuers. Cannot deauthorize the owner.
     * @param issuer The address to deauthorize
     */
    function deauthorizeIssuer(address issuer) external onlyOwner validAddress(issuer) {
        require(
            issuer != owner,
            "CertificateVerifier: cannot deauthorize the owner"
        );
        require(
            authorizedIssuers[issuer],
            "CertificateVerifier: issuer is not authorized"
        );
        
        authorizedIssuers[issuer] = false;
        emit IssuerDeauthorized(issuer, msg.sender);
    }
    
    /**
     * @notice Issues a new certificate on the blockchain
     * @dev Only authorized issuers can issue certificates. Certificate hash must be unique.
     * @param certificateHash The unique hash identifier for the certificate (must not be empty)
     * @param metadata Additional metadata for the certificate (can be empty string)
     */
    function issueCertificate(
        string memory certificateHash,
        string memory metadata
    ) external onlyAuthorizedIssuer {
        // Validate that certificate hash is not empty
        require(
            bytes(certificateHash).length > 0,
            "CertificateVerifier: certificate hash cannot be empty"
        );
        
        // Check if certificate already exists
        require(
            !certificateExists[certificateHash],
            "CertificateVerifier: certificate already exists"
        );
        
        // Create and store the certificate
        certificates[certificateHash] = Certificate({
            certificateHash: certificateHash,
            issuer: msg.sender,
            timestamp: block.timestamp,
            isRevoked: false,
            metadata: metadata
        });
        
        // Mark certificate as existing and increment counter
        certificateExists[certificateHash] = true;
        totalCertificates++;
        
        // Emit event for off-chain tracking
        emit CertificateIssued(certificateHash, msg.sender, block.timestamp);
    }
    
    /**
     * @notice Verifies a certificate's existence and retrieves its details
     * @dev Returns all certificate information if it exists, otherwise returns default values
     * @param certificateHash The hash of the certificate to verify
     * @return exists Boolean indicating if the certificate exists
     * @return issuer Address of the certificate issuer
     * @return timestamp Block timestamp when the certificate was issued
     * @return isRevoked Boolean indicating if the certificate has been revoked
     * @return metadata Additional metadata associated with the certificate
     */
    function verifyCertificate(
        string memory certificateHash
    )
        external
        view
        returns (
            bool exists,
            address issuer,
            uint256 timestamp,
            bool isRevoked,
            string memory metadata
        )
    {
        // Check if certificate exists
        exists = certificateExists[certificateHash];
        
        // If certificate exists, return its details
        if (exists) {
            Certificate memory cert = certificates[certificateHash];
            issuer = cert.issuer;
            timestamp = cert.timestamp;
            isRevoked = cert.isRevoked;
            metadata = cert.metadata;
        } else {
            // Return default values if certificate doesn't exist
            issuer = address(0);
            timestamp = 0;
            isRevoked = false;
            metadata = "";
        }
    }
    
    /**
     * @notice Revokes a certificate, marking it as invalid
     * @dev Only the original issuer or the contract owner can revoke a certificate
     * @param certificateHash The hash of the certificate to revoke
     */
    function revokeCertificate(string memory certificateHash) external {
        // Validate that certificate exists
        require(
            certificateExists[certificateHash],
            "CertificateVerifier: certificate does not exist"
        );
        
        // Get certificate for authorization check
        Certificate storage cert = certificates[certificateHash];
        
        // Check if certificate is already revoked
        require(
            !cert.isRevoked,
            "CertificateVerifier: certificate is already revoked"
        );
        
        // Verify authorization: only issuer or owner can revoke
        require(
            cert.issuer == msg.sender || msg.sender == owner,
            "CertificateVerifier: not authorized to revoke this certificate"
        );
        
        // Mark certificate as revoked
        cert.isRevoked = true;
        
        // Emit event for off-chain tracking
        emit CertificateRevoked(certificateHash, msg.sender);
    }
    
    /**
     * @notice Transfers ownership of the contract to a new address
     * @dev Only the current owner can transfer ownership. New owner must not be zero address.
     * @param newOwner The address to transfer ownership to
     */
    function transferOwnership(address newOwner) external onlyOwner validAddress(newOwner) {
        address oldOwner = owner;
        owner = newOwner;
        
        // Automatically authorize the new owner if not already authorized
        if (!authorizedIssuers[newOwner]) {
            authorizedIssuers[newOwner] = true;
            emit IssuerAuthorized(newOwner, oldOwner);
        }
        
        emit OwnershipTransferred(oldOwner, newOwner);
    }
    
    /**
     * @notice Checks if an address is authorized to issue certificates
     * @param issuer The address to check
     * @return Boolean indicating if the address is authorized
     */
    function isAuthorizedIssuer(address issuer) external view returns (bool) {
        return authorizedIssuers[issuer];
    }
    
    /**
     * @notice Gets the total number of certificates issued
     * @return The total count of certificates
     */
    function getTotalCertificates() external view returns (uint256) {
        return totalCertificates;
    }
}