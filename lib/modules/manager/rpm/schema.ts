import { z } from 'zod';

export const RedHatRPMLockfile = z.object({
  lockfileVersion: z.number(),
  lockfileVendor: z.string(),
  arches: z.array(
    z.object({
      arch: z.string(),
      packages: z.array(
        z.object({
          url: z.string(),
          repoid: z.string(),
          size: z.number(),
          checksum: z.string(),
          name: z.string(),
          evr: z.string(),
          sourcerpm: z.string(),
        })
      ),
    }),
  ),
});

export type RedHatRPMLockfileDefinition = z.infer<typeof RedHatRPMLockfile>;
