// Public entry. The package is being built layer by layer (see docs/architecture.md); nothing is
// exported yet except its status, so a consumer cannot depend on anything unfinished.
export const STATUS = 'scaffold' as const;
