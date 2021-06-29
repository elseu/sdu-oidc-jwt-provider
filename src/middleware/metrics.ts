import * as Koa from "koa";
import { AppSessionState } from "./app-session";

const metrics = (ctx: Koa.ParameterizedContext<AppSessionState>) => {};
