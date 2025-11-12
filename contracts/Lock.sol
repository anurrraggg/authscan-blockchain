// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Uncomment this line to use console.log for debugging
// import "hardhat/console.sol";

/**
 * @title Lock
 * @author AuthScan Blockchain
 * @notice A time-locked contract that holds funds until a specified unlock time
 * @dev This contract allows users to lock Ether for a specific duration.
 *      Funds can only be withdrawn after the unlock time has passed.
 *      Useful for escrow, vesting, or time-delayed payments.
 */
contract Lock {
    /**
     * @notice The timestamp when funds can be withdrawn
     * @dev Unix timestamp (seconds since epoch) representing when the lock expires
     */
    uint256 public unlockTime;
    
    /**
     * @notice The address that owns the locked funds
     * @dev Only this address can withdraw funds after the unlock time
     */
    address payable public owner;
    
    /**
     * @notice The amount of Ether initially locked in the contract
     * @dev Useful for tracking the original deposit amount
     */
    uint256 public lockedAmount;
    
    /**
     * @notice Event emitted when funds are withdrawn from the contract
     * @param amount The amount of Ether withdrawn (in wei)
     * @param when The timestamp when the withdrawal occurred
     */
    event Withdrawal(uint256 amount, uint256 when);
    
    /**
     * @notice Event emitted when funds are deposited into the contract
     * @param depositor The address that deposited the funds
     * @param amount The amount of Ether deposited (in wei)
     * @param unlockTime The timestamp when these funds can be withdrawn
     */
    event FundsDeposited(
        address indexed depositor,
        uint256 amount,
        uint256 unlockTime
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
        require(msg.sender == owner, "Lock: caller is not the owner");
        _;
    }
    
    /**
     * @notice Modifier to check if the unlock time has passed
     * @dev Reverts the transaction if the current time is before unlock time
     */
    modifier onlyAfterUnlock() {
        require(
            block.timestamp >= unlockTime,
            "Lock: unlock time has not been reached"
        );
        _;
    }
    
    /**
     * @notice Constructor initializes the lock with a specific unlock time
     * @dev The contract can receive Ether during deployment. Unlock time must be in the future.
     * @param _unlockTime Unix timestamp (seconds) when funds can be withdrawn
     */
    constructor(uint256 _unlockTime) payable {
        // Validate that unlock time is in the future
        require(
            block.timestamp < _unlockTime,
            "Lock: unlock time must be in the future"
        );
        
        // Set unlock time and owner
        unlockTime = _unlockTime;
        owner = payable(msg.sender);
        
        // Record the initial deposit amount if any Ether was sent
        if (msg.value > 0) {
            lockedAmount = msg.value;
            emit FundsDeposited(msg.sender, msg.value, _unlockTime);
        }
    }
    
    /**
     * @notice Allows the owner to withdraw all funds after the unlock time
     * @dev Can only be called by the owner and only after unlock time has passed.
     *      Transfers the entire contract balance to the owner.
     */
    function withdraw() external onlyOwner onlyAfterUnlock {
        // Get the current balance of the contract
        uint256 balance = address(this).balance;
        
        // Ensure there are funds to withdraw
        require(balance > 0, "Lock: no funds available to withdraw");
        
        // Uncomment this line for debugging (requires hardhat/console.sol import)
        // console.log("Unlock time is %o and block timestamp is %o", unlockTime, block.timestamp);
        
        // Emit event before transferring funds
        emit Withdrawal(balance, block.timestamp);
        
        // Transfer all funds to the owner
        // Using transfer() which forwards 2300 gas and reverts on failure
        owner.transfer(balance);
    }
    
    /**
     * @notice Allows additional funds to be deposited into the lock
     * @dev Anyone can deposit funds, but only the owner can withdraw them.
     *      The unlock time remains the same as set during construction.
     */
    function deposit() external payable {
        require(msg.value > 0, "Lock: deposit amount must be greater than zero");
        
        // Update locked amount if this is the first deposit after construction
        if (lockedAmount == 0 && address(this).balance == msg.value) {
            lockedAmount = msg.value;
        }
        
        emit FundsDeposited(msg.sender, msg.value, unlockTime);
    }
    
    /**
     * @notice Transfers ownership of the contract to a new address
     * @dev Only the current owner can transfer ownership. New owner must not be zero address.
     * @param newOwner The address to transfer ownership to
     */
    function transferOwnership(address payable newOwner) external onlyOwner {
        require(newOwner != address(0), "Lock: new owner cannot be zero address");
        require(newOwner != owner, "Lock: new owner must be different from current owner");
        
        address oldOwner = owner;
        owner = newOwner;
        
        emit OwnershipTransferred(oldOwner, newOwner);
    }
    
    /**
     * @notice Gets the current balance of the contract
     * @return The current balance in wei
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @notice Gets the time remaining until unlock
     * @return The number of seconds remaining until unlock time (0 if already unlocked)
     */
    function getTimeRemaining() external view returns (uint256) {
        if (block.timestamp >= unlockTime) {
            return 0;
        }
        return unlockTime - block.timestamp;
    }
    
    /**
     * @notice Checks if the lock has been unlocked (time has passed)
     * @return Boolean indicating if funds can be withdrawn
     */
    function isUnlocked() external view returns (bool) {
        return block.timestamp >= unlockTime;
    }
    
    /**
     * @notice Fallback function to receive Ether
     * @dev Allows the contract to receive Ether through direct transfers
     */
    receive() external payable {
        if (msg.value > 0) {
            emit FundsDeposited(msg.sender, msg.value, unlockTime);
        }
    }
}
