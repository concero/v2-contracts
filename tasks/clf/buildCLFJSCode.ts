/*
Replaces environment variables in a file and saves the result to a dist folder.
run with: yarn hardhat clf-build-script --path ./CLFScripts/DST.js
 */

import { task, types } from "hardhat/config";
import fs from "fs";
import path from "path";

export const pathToScript = [__dirname, "../", "../", "./clf/"];

function checkFileAccessibility(filePath) {
    if (!fs.existsSync(filePath)) {
        console.error(`The file ${filePath} does not exist.`);
        process.exit(1);
    }
}

/* replaces any strings of the form ${VAR_NAME} with the value of the environment variable VAR_NAME */
function replaceEnvironmentVariables(content) {
    let missingVariable = false;
    const updatedContent = content.replace(/'\${(.*?)}'/g, (match, variable) => {
        const value = process.env[variable];

        if (value === undefined) {
            console.error(`Environment variable ${variable} is missing.`);
            process.exit(1);
        }
        return `'${value}'`;
    });

    if (missingVariable) {
        console.error("One or more environment variables are missing.");
        process.exit(1);
    }
    return updatedContent;
}

function saveProcessedFile(content, outputPath) {
    const outputDir = path.join(...pathToScript, "dist/");

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir);
    }
    const outputFile = path.join(outputDir, path.basename(outputPath));
    fs.writeFileSync(outputFile, content, "utf8");
    console.log(`Saved to ${outputFile}`);
}

function cleanupFile(content) {
    const marker = "/*BUILD_REMOVES_EVERYTHING_ABOVE_THIS_LINE*/";
    const index = content.indexOf(marker);
    if (index !== -1) content = content.substring(index + marker.length);
    return content
        .replace(/^\s*\/\/.*$/gm, "") // Remove single-line comments that might be indented
        .replace(/\/\*[\s\S]*?\*\//g, "") // Remove multi-line comments
        .replace(/^\s*[\r\n]/gm, ""); // Remove empty lines
}

function minifyFile(content) {
    return content
        .replace(/\n/g, " ") // Remove newlines
        .replace(/\t/g, " ") // Remove tabs
        .replace(/\s\s+/g, " "); // Replace multiple spaces with a single space
}

export function buildScript(fileToBuild: string) {
    if (!fileToBuild) {
        console.error("Path to Functions script file is required.");
        return;
    }

    checkFileAccessibility(fileToBuild);

    try {
        const fileContent = fs.readFileSync(fileToBuild, "utf8");
        const cleanedUpFile = replaceEnvironmentVariables(cleanupFile(fileContent));
        const minifiedFile = minifyFile(cleanedUpFile);

        saveProcessedFile(cleanedUpFile, fileToBuild);
        saveProcessedFile(minifiedFile, fileToBuild.replace(".js", ".min.js"));
    } catch (err) {
        console.error(`Error processing file ${fileToBuild}: ${err}`);
        process.exit(1);
    }
}

// run with: yarn hardhat clf-script-build
task("clf-script-build", "Builds the JavaScript source code")
    .addFlag("all", "Build all scripts")
    .addOptionalParam("file", "Path to Functions script file", undefined, types.string)
    .setAction(async (taskArgs, hre) => {
        if (taskArgs.all) {
            const paths = ["src/"];

            paths.forEach((_path: string) => {
                const files = fs.readdirSync(path.join(...pathToScript, _path));

                files.forEach((file: string) => {
                    if (file.endsWith(".js")) {
                        const fileToBuild = path.join(...pathToScript, _path, file);
                        buildScript(fileToBuild);
                    }
                });
            });

            return;
        }
        if (taskArgs.file) {
            const fileToBuild = path.join(...pathToScript, "src", taskArgs.file);
            buildScript(fileToBuild);
        } else {
            console.error("No file specified.");
            process.exit(1);
        }
    });

export default {};
