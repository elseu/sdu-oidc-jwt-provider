import { Histogram } from "prom-client";

const logins = new Histogram({ name: "asdfasdf", help: "Login tries" });
