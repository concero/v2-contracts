// SPDX-License-Identifier: UNLICENSED
/**
 * @title Security Reporting
 * @notice If you discover any security vulnerabilities, please report them responsibly.
 * @contact email: security@concero.io
 */
pragma solidity 0.8.28;

import {Test} from "forge-std/src/Test.sol";
import {CreValidatorLib} from "../../../contracts/validators/CreValidatorLib/CreValidatorLib.sol";
import {EcdsaValidatorLib} from "../../../contracts/validators/CreValidatorLib/EcdsaValidatorLib.sol";
import {MessageCodec} from "../../../contracts/common/libraries/MessageCodec.sol";
import {ValidatorCodec} from "contracts/common/libraries/ValidatorCodec.sol";
import {CommonErrors} from "contracts/common/CommonErrors.sol";
import {IConceroRouter} from "contracts/interfaces/IConceroRouter.sol";

contract CreValidatorLibTest is Test {
    using ValidatorCodec for bytes;

    CreValidatorLib internal s_validatorLib = new CreValidatorLib();

    address internal s_signer1 = 0x4d7D71C7E584CfA1f5c06275e5d283b9D3176924;
    address internal s_signer2 = 0x1A89c98E75983Ec384AD8e83EAf7D0176eEaF155;
    address internal s_signer3 = 0xdE5CD1dD4300A0b4854F8223add60D20e1dFe21b;
    address internal s_signer4 = 0x4D6CFd44F94408a39fB1af94a53c107A730ba161;
    address internal s_signer5 = 0xF3BAa9A99B5ad64f50779F449Bac83bAAC8bfDb6;
    address internal s_signer6 = 0xD7F22fB5382ff477d2fF5c702cAB0EF8abf18233;
    address internal s_signer7 = 0xcdf20F8FFD41B02c680988b20e68735cc8C1ca17;
    address internal s_signer8 = 0xff9b062fcCb2f042311343048b9518068370F837;
    address internal s_signer9 = 0x4f99b550623e77B807df7cbED9C79D55E1163B48;

    bytes32 internal s_creWorkflowId =
        0x005abdaec2b4e01b66d0b021ecb27d59ccf2868968de657c7ded9c37a3b03a10;

    function setUp() public {
        s_validatorLib.initialize(address(this));

        address[] memory signers = new address[](9);
        signers[0] = s_signer1;
        signers[1] = s_signer2;
        signers[2] = s_signer3;
        signers[3] = s_signer4;
        signers[4] = s_signer5;
        signers[5] = s_signer6;
        signers[6] = s_signer7;
        signers[7] = s_signer8;
        signers[8] = s_signer9;

        bool[] memory isAllowedArr = new bool[](signers.length);
        for (uint256 i; i < isAllowedArr.length; ++i) {
            isAllowedArr[i] = true;
        }

        s_validatorLib.setAllowedSigners(signers, isAllowedArr);
        s_validatorLib.setMinSignersCount(uint8(signers.length));
        s_validatorLib.setIsWorkflowIdAllowed(s_creWorkflowId, true);
    }

    // function test_validateSignatures_success() public view {
    //     assert(s_validatorLib.isValid(_getMessageReceipt(), _getValidation()));
    // }

    function test_validateSignatures_InvalidSignaturesCount_revert() public {
        bytes[] memory signatures = _getSignatures();
        s_validatorLib.setMinSignersCount(s_validatorLib.getMinSignersCount() + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                EcdsaValidatorLib.InvalidSignaturesCount.selector,
                signatures.length,
                s_validatorLib.getMinSignersCount()
            )
        );
        s_validatorLib.isValid(_getMessageReceipt(), _getValidation(signatures));
    }

    function test_validateSignatures_InvalidSigner_revert() public {
        bytes[] memory signatures = _getSignatures();
        signatures[0][3] = bytes1(uint8(1));

        vm.expectRevert(
            abi.encodeWithSelector(
                EcdsaValidatorLib.InvalidSigner.selector,
                0x354Fd1D36b72268eFD2B8611910708Eb44312F84
            )
        );
        s_validatorLib.isValid(_getMessageReceipt(), _getValidation(signatures));
    }

    function test_validateSignatures_DuplicateSigner_revert() public {
        bytes[] memory signatures = _getSignatures();
        signatures[4] = signatures[1];

        vm.expectRevert(
            abi.encodeWithSelector(EcdsaValidatorLib.DuplicateSigner.selector, s_signer2)
        );
        s_validatorLib.isValid(_getMessageReceipt(), _getValidation(signatures));
    }

    function test_validateSignatures_InvalidCreWorkflowId_revert() public {
        s_validatorLib.setIsWorkflowIdAllowed(s_creWorkflowId, false);

        vm.expectRevert(
            abi.encodeWithSelector(CreValidatorLib.InvalidCreWorkflowId.selector, s_creWorkflowId)
        );
        s_validatorLib.isValid(_getMessageReceipt(), _getValidation());
    }

    function testFuzz_setWorkflowId(bytes32 workflowId, bool isAllowed) public {
        s_validatorLib.setIsWorkflowIdAllowed(workflowId, isAllowed);
        assert(s_validatorLib.isWorkflowIdAllowed(workflowId) == isAllowed);
    }

    function testFuzz_getFeeAndValidatorConfig(uint24 chainSelector, uint32 gasLimit) public {
        uint32[] memory gasLimits = new uint32[](1);
        gasLimits[0] = gasLimit;

        uint24[] memory chainSelectors = new uint24[](1);
        chainSelectors[0] = chainSelector;

        s_validatorLib.setDstChainGasLimits(chainSelectors, gasLimits);

        (, bytes memory validatorConfig) = s_validatorLib.getFeeAndValidatorConfig(
            _buildMessageRequest(chainSelector, gasLimit)
        );

        assert(validatorConfig.evmConfig() == gasLimit);
    }

    function testFuzz_setAllowedSigners_success(address[] memory signers) public {
        bool[] memory isAllowedArr = new bool[](signers.length);
        for (uint256 i; i < isAllowedArr.length; ++i) {
            isAllowedArr[i] = true;
        }

        s_validatorLib.setAllowedSigners(signers, isAllowedArr);

        for (uint256 i; i < signers.length; ++i) {
            assert(s_validatorLib.isSignerAllowed(signers[i]));
        }

        for (uint256 i; i < isAllowedArr.length; ++i) {
            isAllowedArr[i] = false;
        }

        s_validatorLib.setAllowedSigners(signers, isAllowedArr);

        for (uint256 i; i < signers.length; ++i) {
            assert(s_validatorLib.isSignerAllowed(signers[i]) == false);
        }
    }

    function testFuzz_setMinSignersCount_success(uint8 minSignersCount) public {
        s_validatorLib.setMinSignersCount(minSignersCount);
        assert(s_validatorLib.getMinSignersCount() == minSignersCount);
    }

    function testFuzz_setDstChainGasLimits(uint24[] calldata chainSelectors) public {
        uint32[] memory gasLimits = new uint32[](chainSelectors.length);
        for (uint256 i; i < chainSelectors.length; ++i) {
            gasLimits[i] = (chainSelectors[i] % 5) * 100;
        }

        s_validatorLib.setDstChainGasLimits(chainSelectors, gasLimits);

        for (uint256 i; i < chainSelectors.length; ++i) {
            assert(s_validatorLib.getDstChainGasLimit(chainSelectors[i]) == gasLimits[i]);
        }
    }

    function testFuzz_setDstChainGasLimits_Unauthorized_revert(
        uint24[] calldata chainSelectors
    ) public {
        uint32[] memory gasLimits = new uint32[](chainSelectors.length);
        for (uint256 i; i < chainSelectors.length; ++i) {
            gasLimits[i] = (chainSelectors[i] % 5) * 100;
        }

        vm.prank(makeAddr("fake admin"));
        vm.expectRevert(
            "AccessControl: account 0xf27a21f2bffe296e9b45ed70680e8410d81d2e95 is missing role 0xdf8b4c520ffe197c5343c6f5aec59570151ef9a492f2c624fd45ddde6135ec42"
        );
        s_validatorLib.setDstChainGasLimits(chainSelectors, gasLimits);
    }

    function testFuzz_initialize_revert(address fakeAdmin) public {
        vm.expectRevert("Initializable: contract is already initialized");
        s_validatorLib.initialize(fakeAdmin);
    }

    function test_setAllowedSignersAccessControl_revert() public {
        address fakeAdmin = makeAddr("fakeAdmin");
        vm.expectRevert(
            "AccessControl: account 0x3306edf2df2adba41a53cae2db0c1610ebcf13b9 is missing role 0xdf8b4c520ffe197c5343c6f5aec59570151ef9a492f2c624fd45ddde6135ec42"
        );
        vm.prank(fakeAdmin);
        s_validatorLib.setAllowedSigners(new address[](1), new bool[](1));
    }

    function test_setMinSignersCountAccessControl_revert() public {
        address fakeAdmin = makeAddr("fakeAdmin");
        vm.expectRevert(
            "AccessControl: account 0x3306edf2df2adba41a53cae2db0c1610ebcf13b9 is missing role 0xdf8b4c520ffe197c5343c6f5aec59570151ef9a492f2c624fd45ddde6135ec42"
        );
        vm.prank(fakeAdmin);
        s_validatorLib.setMinSignersCount(uint8(1));
    }

    function test_setIsWorkflowIdAllowedAccessControl_revert() public {
        address fakeAdmin = makeAddr("fakeAdmin");
        vm.expectRevert(
            "AccessControl: account 0x3306edf2df2adba41a53cae2db0c1610ebcf13b9 is missing role 0xdf8b4c520ffe197c5343c6f5aec59570151ef9a492f2c624fd45ddde6135ec42"
        );
        vm.prank(fakeAdmin);
        s_validatorLib.setIsWorkflowIdAllowed(s_creWorkflowId, false);
    }

    function test_getFee_RevertsIfFeeTokenIsNotSupported() public {
        address unsupportedFeeToken = makeAddr("UnsupportedFeeToken");
        IConceroRouter.MessageRequest memory messageRequest = _buildMessageRequest(1000, 100_000);
        messageRequest.feeToken = unsupportedFeeToken;

        vm.expectRevert(
            abi.encodeWithSelector(CommonErrors.FeeTokenNotSupported.selector, unsupportedFeeToken)
        );

        s_validatorLib.getFee(messageRequest);
    }

    function test_isFeeTokenSupported() public {
        assertTrue(s_validatorLib.isFeeTokenSupported(address(0)));
        assertFalse(s_validatorLib.isFeeTokenSupported(makeAddr("UnsupportedFeeToken")));
    }

    function test_getGasLimitsForChains() public {
        uint24 chainSelector1 = 1000;
        uint24 chainSelector2 = 2000;
        uint32 gasLimit1 = 100_000;
        uint32 gasLimit2 = 200_000;

        uint24[] memory chainSelectors = new uint24[](2);
        chainSelectors[0] = chainSelector1;
        chainSelectors[1] = chainSelector2;

        uint32[] memory gasLimits = new uint32[](2);
        gasLimits[0] = gasLimit1;
        gasLimits[1] = gasLimit2;

        s_validatorLib.setDstChainGasLimits(chainSelectors, gasLimits);

        uint32[] memory retrievedGasLimits = s_validatorLib.getGasLimitsForChains(chainSelectors);

        assertEq(retrievedGasLimits[0], gasLimit1);
        assertEq(retrievedGasLimits[1], gasLimit2);
    }

    function test_getGasLimitsForChains_gas() public {
        vm.pauseGasMetering();
        uint256 chainAmount = 10_000;

        uint24[] memory chainSelectors = new uint24[](chainAmount);
        uint32[] memory gasLimits = new uint32[](chainAmount);

        for (uint256 i; i < chainAmount; ++i) {
            chainSelectors[i] = uint24(i + 1);
            gasLimits[i] = uint32((i + 1) * 100_000);
        }

        s_validatorLib.setDstChainGasLimits(chainSelectors, gasLimits);

        vm.resumeGasMetering();
        uint32[] memory retrievedGasLimits = s_validatorLib.getGasLimitsForChains(chainSelectors);
        vm.pauseGasMetering();
    }

    // INTERNAL FUNCTIONS

    function _getValidation() internal pure returns (bytes memory) {
        return _getValidation(_getSignatures());
    }

    function _getValidation(bytes[] memory signatures) internal pure returns (bytes memory) {
        bytes
            memory reportContext = hex"000e8ce31db48e5e44619d24d9dadfc5f22a34db8205b2b25cd831eab02244c50000000000000000000000000000000000000000000000000000000048352a000000000000000000000000000000000000000000000000000000000000000000";
        bytes
            memory rawReport = hex"01115515065110d69856ba0ce52a3993946cfaef9646554f4c5bd166dd4e800ab46929b60e0000000100000001005abdaec2b4e01b66d0b021ecb27d59ccf2868968de657c7ded9c37a3b03a1066666634313464303336dddddb8a8e41c194ac6542a0ad7ba663a72741e00004361850ddbced44d2c34178636e0bb1290024a0979a7ab593fd5c4e99f2a9d616";

        bytes32[] memory proof;

        return abi.encodePacked(rawReport, reportContext, abi.encode(signatures, proof));
    }

    function _getSignatures() internal pure returns (bytes[] memory) {
        bytes
            memory signature1 = hex"d205b207538957f496d4fd150b9400f01aadd78f23afd4362c0cd7f2b11527d4233678d5c25f8465b8e73483f70b0b5ac3cf302182d3058c8d5dc4c03223958b00";
        bytes
            memory signature2 = hex"1e73fa764c60b7e809222a28e3d32b1643725aaf9682f02ebd9555c1229b1bac7d2069bd90119bc52d7e1377223e8b2f10c5e7b00c606bd6c074330e4d63686201";
        bytes
            memory signature3 = hex"0d3ed12934b6ca5670d3375a4072ec5d86a916aea42416719c1bc3eb23e851e310e75bce8954a2ac1a38022934fa2bedb256947bc231e7cdfb9d1a899742da7601";
        bytes
            memory signature4 = hex"fd8a2539e83002e233a7c7bd3104a5ae15d807d1618bc7e2839b042687229c15754067f9564cc2ff4c492d935078a97930bf526970125b8681ddba690f9c82e000";
        bytes
            memory signature5 = hex"7ac9e18e54eb585936dc2142694be016c45d8ab74c6fc6e6966fd57be024d0260effc6e69891ec7f3c39c4c3de6cfe979324a6bdf73acea094ee63388d37424600";
        bytes
            memory signature6 = hex"cba99c1f9efc8ca37e537f00ea9a6947ab847fad4a8351672dda44a5d73d9742115fe76410ed85d00dce2941d48607c1a82903772ce5e84a95c0659f70ea59a300";
        bytes
            memory signature7 = hex"f33f62b1a07d8ed0ba9f438b40c446c521f7b79841ec64a5eaf9ebeafc26a8d4759fff490a885f5b618ce2766a6bf2c22bc4b294cf2cc364eee630f11ddf65de01";
        bytes
            memory signature8 = hex"0ae9258d491714311c75c907c905b1751e6756a115ef902a942a0396af7b24c15a241f402f7196a8eaba1aee4daf2755ce0d8db3255da6bea3cbfafaf315e1cc00";
        bytes
            memory signature9 = hex"88702485aeb04af188eec3b34358b14e6fa726bde84ee993ba7f104259584f5f4f884b6baba74b6609c541acf7494afaeaf793188810746b355fc9a2065e5ae101";

        bytes[] memory signatures = new bytes[](9);
        signatures[0] = signature1;
        signatures[1] = signature2;
        signatures[2] = signature3;
        signatures[3] = signature4;
        signatures[4] = signature5;
        signatures[5] = signature6;
        signatures[6] = signature7;
        signatures[7] = signature8;
        signatures[8] = signature9;

        return signatures;
    }

    function _getMessageReceipt() internal pure returns (bytes memory) {
        bytes
            memory logData = hex"0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010000000000000000000000000047eff953e7d2706cf0cbdd10f7afca8b4080864a000000000000000000000000000000000000000000000000000000000000007a01013882066eee000000000000000000000000000000000000000000000000000000000000000200001cf4b0e5669bb28c21db33bb184e42ecbecf117ef40000000000000000000018bb87f69a7e5ab2269e21fc78152c2f19908b0a49000493e00000010000000100000000000c48656c6c6f20776f726c6421000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000010310f1414ce4c5d1bbd1c4b8f846ea8985b8d9e";

        (bytes memory messageReceipt, , ) = abi.decode(logData, (bytes, address[], address));
        return messageReceipt;
    }

    function _signHash(
        string memory wallet,
        bytes32 hashToSign
    ) internal returns (bytes memory, address) {
        (address signer, uint256 signerPk) = makeAddrAndKey(wallet);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, hashToSign);

        return (abi.encodePacked(r, s, v - 27), signer);
    }

    function _buildMessageRequest(
        uint24 dstChainSelector,
        uint32 dstChainGasLimit
    ) internal returns (IConceroRouter.MessageRequest memory) {
        address[] memory validatorLibs = new address[](1);

        return
            IConceroRouter.MessageRequest({
                dstChainSelector: dstChainSelector,
                srcBlockConfirmations: 0,
                feeToken: address(0),
                dstChainData: MessageCodec.encodeEvmDstChainData(
                    makeAddr("client"),
                    dstChainGasLimit
                ),
                validatorLibs: validatorLibs,
                relayerLib: makeAddr("relayer"),
                validatorConfigs: new bytes[](1),
                relayerConfig: new bytes(1),
                payload: ""
            });
    }
}
