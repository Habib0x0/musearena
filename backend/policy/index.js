// MuseArena CrossGuard deploy gate (design: "Pulumi preview + CrossGuard policy
// pack (mandatory tags, deny open egress, require TTL)"). Plain JS so the pack
// runs without a build step. Every rule is mandatory: a violation fails preview
// and therefore the deploy.
const { PolicyPack } = require("@pulumi/policy");

const REQUIRED_LABELS = ["arena.run_id", "arena.org", "arena.ttl_hours", "arena.spec_digest"];
const labelsOf = (args) => Object.fromEntries((args.labels || []).map((l) => [l.label, l.value]));

new PolicyPack("musearena-deploy-gate", {
  enforcementLevel: "mandatory",
  policies: [
    {
      name: "env-network-internal",
      description: "Target networks must be internal (default-deny egress).",
      validateResource: (args, report) => {
        if (args.type !== "docker:index/network:Network") return;
        if (args.props.internal !== true) report("network must set internal: true (no egress)");
      },
    },
    {
      name: "no-host-exposure",
      description: "Target containers never publish ports or join host/bridge networks.",
      validateResource: (args, report) => {
        if (args.type !== "docker:index/container:Container") return;
        if ((args.props.ports || []).length > 0) report("container publishes host ports");
        // The provider reports networkMode "bridge" as a computed default at
        // preview even when the container joins only networksAdvanced (verified
        // at runtime: attached to the internal net only). So: forbid "host",
        // and require explicit attachment to exactly one named network.
        if (args.props.networkMode === "host") report("container uses host networking");
        const nets = args.props.networksAdvanced || [];
        if (nets.length !== 1) report(`container must join exactly one env network (has ${nets.length})`);
        if (args.props.privileged) report("privileged containers are not allowed");
      },
    },
    {
      name: "mandatory-labels",
      description: "Every network/container carries run, org, TTL and spec-digest labels (sweeper + replay identity).",
      validateResource: (args, report) => {
        if (args.type !== "docker:index/container:Container" && args.type !== "docker:index/network:Network") return;
        const labels = labelsOf(args.props);
        for (const k of REQUIRED_LABELS) if (!labels[k]) report(`missing label ${k}`);
      },
    },
    {
      name: "ttl-required",
      description: "TTL must be a positive number of hours within the platform maximum.",
      validateResource: (args, report) => {
        if (args.type !== "docker:index/container:Container" && args.type !== "docker:index/network:Network") return;
        const ttl = Number(labelsOf(args.props)["arena.ttl_hours"]);
        if (!(ttl > 0) || ttl > 72) report(`arena.ttl_hours must be in (0, 72], got ${labelsOf(args.props)["arena.ttl_hours"]}`);
      },
    },
  ],
});
