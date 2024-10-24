import { task } from "hardhat/config";
import { compileContracts } from "../../utils";
import { ProxyEnum } from "../../constants";
import deployConceroRouter from "../../deploy/ConceroRouter";
import deployProxyAdmin from "../../deploy/ConceroProxyAdmin";
import deployTransparentProxy from "../../deploy/TransparentProxy";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { setVariables } from "./setVariables";
import { upgradeProxyImplementation } from "../upgradeProxyImplementation";

export async function deployRouterTask(taskArgs: any, hre: HardhatRuntimeEnvironment) {
    compileContracts({ quiet: true });

    //todo: when running --deployproxy W/O --deployimplementation,
    //the initial proxy implementation is set to paused, but should be set to existing latest impl. from env.
    if (taskArgs.deployproxy) {
        await deployProxyAdmin(hre, ProxyEnum.routerProxy);
        await deployTransparentProxy(hre, ProxyEnum.routerProxy);
    }

    if (taskArgs.deployimplementation) {
        await deployConceroRouter(hre);
        await upgradeProxyImplementation(hre, ProxyEnum.routerProxy, false);
    }

    if (taskArgs.setvars) {
        await setVariables(hre);
    }
}

task("deploy-router", "Deploy the ConceroRouter contract")
    .addFlag("deployproxy", "Deploy the proxy")
    .addFlag("deployimplementation", "Deploy the implementation")
    .addFlag("setvars", "Set the contract variables")
    .setAction(async (taskArgs, hre: HardhatRuntimeEnvironment) => {
        await deployRouterTask(taskArgs, hre);
    });

export default {};
