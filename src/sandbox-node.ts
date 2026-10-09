// Registers the `node:vm` sandbox. Imported by the Node entry points only, so
// a browser bundle of the engine never sees `node:vm`.
import * as vm from 'node:vm';
import { nodeSandboxFactory, setSandboxFactory } from './sandbox.js';

setSandboxFactory(nodeSandboxFactory(vm));
