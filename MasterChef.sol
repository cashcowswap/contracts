// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "@openzeppelin/contracts/math/SafeMath.sol";
import "./libs/IBEP20.sol";
import "./libs/SafeBEP20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./CCDIToken.sol";
import "./SponsorToken.sol";
import "./SponsorPool.sol";

// MasterChef is the master of CCDI. He can make CCDI and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once CCDI is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract MasterChef is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeBEP20 for IBEP20;

    // Info of each user.
    struct UserInfo {
        uint256 amount;         // How many LP tokens the user has provided.
        uint256 rewardDebt;     // Reward debt. See explanation below.
        uint256 locking;
        uint256 pending;
        uint256 lastLockTime;
        //
        // We do some fancy math here. Basically, any point in time, the amount of CCDIS
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accSailPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accSailPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IBEP20 lpToken;           // Address of LP token contract.
        uint256 allocPoint;       // How many allocation points assigned to this pool. CCDIS to distribute per block.
        uint256 lastRewardBlock;  // Last block number that CCDIS distribution occurs.
        uint256 accSailPerShare;   // Accumulated CCDIS per share, times 1e12. See below.
        uint16 depositFeeBP;      // Deposit fee in basis points
        uint256 lockTime;  
        uint256 startBlock;        
        uint256 endBlock;  
    }

    // The CCDI TOKEN!
    CCDIToken  public ccdi;
    // The SPON TOKEN!
    IBEP20 public spon;
    // The BUSD capital for SPON pool!
    SponsorPool public sponPool;  
    // Dev address.
    address public devAddress;
    // Deposit Fee address
    address public feeAddress;
    // CCDI tokens created per block.
    uint256 public ccdiPerBlock = 1 ether;
    // Bonus muliplier for early ccdi makers.
    uint256 public constant BONUS_MULTIPLIER = 1;
    // Burn address
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;
    // Burn rate for CCDI
    uint256 public constant BURN_RATE = 3;
    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;
    // The block number when CCDI mining starts.
    uint256 public startBlock;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);

  

    constructor(
        CCDIToken _ccdi,
        IBEP20 _spon,
        SponsorPool _sponPool,
        uint256 _startBlock,
        uint256 _ccdiPerBlock
    ) public {
        ccdi = _ccdi;
        spon = _spon;
        sponPool = _sponPool;   
        startBlock = _startBlock;
        ccdiPerBlock = _ccdiPerBlock;
        feeAddress = msg.sender;
        devAddress = msg.sender;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    function blockNumber() external view returns (uint256) {
        return block.number;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    function add(uint256 _allocPoint, IBEP20 _lpToken, uint16 _depositFeeBP, uint256 _lockTime,uint256 _startBlock,uint256 _endBlock, bool _withUpdate) public onlyOwner {
        require(_depositFeeBP <= 10000, "add: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolInfo.push(PoolInfo({
            lpToken: _lpToken,
            allocPoint: _allocPoint,
            lastRewardBlock: lastRewardBlock,
            accSailPerShare: 0,
            depositFeeBP: _depositFeeBP,
            lockTime: _lockTime,
            startBlock:_startBlock,
            endBlock:_endBlock
        }));
    }

    // Update the given pool's CCDI allocation point and deposit fee. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, uint16 _depositFeeBP,uint256 _lockTime,uint256 _startBlock,uint256 _endBlock, bool _withUpdate) public onlyOwner {
        require(_depositFeeBP <= 10000, "set: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
        poolInfo[_pid].lockTime = _lockTime;
        poolInfo[_pid].startBlock =_startBlock;
        poolInfo[_pid].endBlock =_endBlock;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public pure returns (uint256) {
        return _to.sub(_from).mul(BONUS_MULTIPLIER);
    }

    // View function to see pending CCDIS on frontend.
    function getAmount(uint256 _pid, address _user) external view returns (uint256) {
        UserInfo storage user = userInfo[_pid][_user];
        return user.amount;
    }

    // View function to see pending CCDIS on frontend.
    function pendingSail(uint256 _pid, address _user) public view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accSailPerShare = pool.accSailPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if ((block.number > pool.lastRewardBlock&&block.number >= pool.startBlock && (pool.endBlock == 0 || block.number <pool.endBlock))&& lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 sailReward = multiplier.mul(ccdiPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accSailPerShare = accSailPerShare.add(sailReward.mul(1e12).div(lpSupply));
        }
        if(pool.lockTime <= 0){
            return user.pending.add(user.amount.mul(accSailPerShare).div(1e12).sub(user.rewardDebt));
        }
        return user.pending.add((user.amount.mul(accSailPerShare).div(1e12).sub(user.rewardDebt)).div(2));
    }

    function lockingSail(uint256 _pid, address _user) public view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accSailPerShare = pool.accSailPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if ((block.number > pool.lastRewardBlock&&block.number >= pool.startBlock && (pool.endBlock == 0 || block.number <pool.endBlock))&& lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 sailReward = multiplier.mul(ccdiPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accSailPerShare = accSailPerShare.add(sailReward.mul(1e12).div(lpSupply));
        }
        if(pool.lockTime <= 0){
            return 0;
        }
        return user.locking.add((user.amount.mul(accSailPerShare).div(1e12).sub(user.rewardDebt)).div(2));
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        if (block.number < pool.startBlock ) {
            return;
        }
        if (pool.endBlock > 0 && block.number > pool.endBlock ) {
            return;
        }
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 ccdiReward = multiplier.mul(ccdiPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        //ccdi.mint(devaddr, ccdiReward.div(10));
        ccdi.mint(address(this), ccdiReward);
        pool.accSailPerShare = pool.accSailPerShare.add(ccdiReward.mul(1e12).div(lpSupply));
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterChef for CCDI allocation.
    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        if (user.amount > 0) {
            harvest(_pid);
        }else{
            user.lastLockTime = block.timestamp;
        }
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
            if (address(pool.lpToken) == address(ccdi)) {
                uint256 transferTax = _amount.mul(BURN_RATE).div(100);
                _amount = _amount.sub(transferTax);
            }
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.lpToken.safeTransfer(feeAddress, depositFee);
                user.amount = user.amount.add(_amount).sub(depositFee);
            } else {
                user.amount = user.amount.add(_amount);
            }
        }
        user.rewardDebt = user.amount.mul(pool.accSailPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from MasterChef.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        uint256 pending = pendingSail(_pid,msg.sender);
        if (pending > 0) {
            harvest(_pid);
        }
        if (_amount > 0) {
            if(_amount == user.amount){
                uint256 locking = lockingSail(_pid,msg.sender);
                if (locking > 0) {
                    if( block.timestamp < user.lastLockTime.add(pool.lockTime)){
                        emergencHarvestLocking(_pid);
                    }else{
                        harvestLocking(_pid);
                    }
                }
            }
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(msg.sender), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accSailPerShare).div(1e12);
        emit Withdraw(msg.sender, _pid, _amount);
    }

    function withdrawAll(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 _amount = user.amount;
        updatePool(_pid);
        uint256 pending = pendingSail(_pid,msg.sender);
        if (pending > 0) {
            harvest(_pid);
        }
        if (_amount > 0) {
            if(_amount == user.amount){
                uint256 locking = lockingSail(_pid,msg.sender);
                if (locking > 0) {
                    if( block.timestamp < user.lastLockTime.add(pool.lockTime)){
                        emergencHarvestLocking(_pid);
                    }else{
                        harvestLocking(_pid);
                    }
                }
            }
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(msg.sender), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accSailPerShare).div(1e12);
        emit Withdraw(msg.sender, _pid, _amount);
    }

    function harvest(uint256 _pid) public  {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        _harvest(_pid);
        user.rewardDebt = user.amount.mul(pool.accSailPerShare).div(1e12);
    }

    function _harvest(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount > 0, "nothing to harvest");
        uint256 pending = (user.amount.mul(pool.accSailPerShare).div(1e12).sub(user.rewardDebt)).div(2);
        uint256 locking = (user.amount.mul(pool.accSailPerShare).div(1e12).sub(user.rewardDebt)).div(2);
        uint256 award =  user.pending.add(pending);
        user.pending = 0;
        if(pool.lockTime <= 0){
            award = award.add(locking);
        }else{
            user.locking = user.locking.add(locking);
        }
        safeCCDITransfer(msg.sender,award);
        if (address(pool.lpToken) == address(spon)) {
            sponPool.transfer(address(msg.sender), award.mul(5).div(100));
        }
        user.lastLockTime = block.timestamp;
    }

    function harvestLocking(uint256 _pid) public  {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        _harvestLocking(_pid);
        user.rewardDebt = user.amount.mul(pool.accSailPerShare).div(1e12);
    }

    function emergencHarvestLocking(uint256 _pid) public  {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        _emergencHarvestLocking(_pid);
        user.rewardDebt = user.amount.mul(pool.accSailPerShare).div(1e12);
    }

    function _harvestLocking(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount > 0, "nothing to harvest");
        require( block.timestamp >= user.lastLockTime.add(pool.lockTime) , 'must after unlock');
        uint256 pending = user.amount.mul(pool.accSailPerShare).div(1e12).sub(user.rewardDebt).div(2);
        uint256 locking = user.amount.mul(pool.accSailPerShare).div(1e12).sub(user.rewardDebt).div(2);
        user.pending = user.pending.add(pending);
        user.lastLockTime = block.timestamp;
        safeCCDITransfer(msg.sender, user.locking.add(locking));
        user.locking = 0;
    }

    function _emergencHarvestLocking(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount > 0, "nothing to harvest");
        require(block.timestamp < user.lastLockTime.add(pool.lockTime), 'must local time');
        uint256 pending = user.amount.mul(pool.accSailPerShare).div(1e12).sub(user.rewardDebt).div(2);
        uint256 locking = user.amount.mul(pool.accSailPerShare).div(1e12).sub(user.rewardDebt).div(2);
        user.pending = user.pending.add(pending);
        safeCCDITransfer(msg.sender, (user.locking.add(locking)).div(2));
        safeCCDITransfer(BURN_ADDRESS,(user.locking.add(locking)).div(2));
        user.locking = 0;
        user.lastLockTime = block.timestamp;
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        user.pending = 0;
        user.locking = 0;
        pool.lpToken.safeTransfer(address(msg.sender), amount);
        user.lastLockTime = block.timestamp;
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    // Safe ccdi transfer function, just in case if rounding error causes pool to not have enough CCDIS.
    function safeCCDITransfer(address _to, uint256 _amount) internal {
        uint256 sailBal = ccdi.balanceOf(address(this));
        bool transferSuccess = false;
        if (_amount > sailBal) {
            transferSuccess = ccdi.transfer(_to, sailBal);
        } else {
            transferSuccess = ccdi.transfer(_to, _amount);
        }
        require(transferSuccess, "safeSailTransfer: Transfer failed");
    }

    // Update dev address by the previous dev.
    function setDevAddress(address _devAddress) public {
        require(msg.sender == devAddress, "setDevAddress: FORBIDDEN");
        devAddress = _devAddress;
    }

    function setFeeAddress(address _feeAddress) public {
        require(msg.sender == feeAddress, "setFeeAddress: FORBIDDEN");
        feeAddress = _feeAddress;
    }

    function setStartBlock(uint256 _startBlock) public {
        require(msg.sender == devAddress, "setStartBlock: FORBIDDEN");
        startBlock = _startBlock;
    }

    function setCCDIPerBlock(uint256 _ccdiPerBlock) public {
        require(msg.sender == devAddress, "setStartBlock: FORBIDDEN");
        ccdiPerBlock = _ccdiPerBlock;   
    }

    function setSponsorPool(SponsorPool _sponPool) public {
        require(msg.sender == devAddress, "setStartBlock: FORBIDDEN");
        sponPool = _sponPool;   
    }
}