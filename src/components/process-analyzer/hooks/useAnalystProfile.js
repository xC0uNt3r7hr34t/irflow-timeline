import { useEffect, useRef } from "react";
import useUIStore from "../../../store/useUIStore.js";
import { PI_ANALYST_PROFILE_DEFAULT } from "../constants.js";

export default function useAnalystProfile() {
  const piAnalystProfile = useUIStore((s) => s.piAnalystProfile);
  const setPiAnalystProfile = useUIStore((s) => s.setPiAnalystProfile);
  const loadedRef = useRef(false);
  const tle = typeof window !== "undefined" ? window.tle : null;

  useEffect(() => {
    if (!tle?.loadPiAnalystProfile) return;
    let cancelled = false;
    tle.loadPiAnalystProfile()
      .then((profile) => {
        if (cancelled) return;
        setPiAnalystProfile({
          ...PI_ANALYST_PROFILE_DEFAULT,
          ...(profile || {}),
          suppressions: Array.isArray(profile?.suppressions) ? profile.suppressions : [],
          baselines: Array.isArray(profile?.baselines) ? profile.baselines : [],
        });
        loadedRef.current = true;
      })
      .catch(() => {
        if (cancelled) return;
        loadedRef.current = true;
      });
    return () => { cancelled = true; };
  }, [tle]);

  useEffect(() => {
    if (!tle?.savePiAnalystProfile || !loadedRef.current) return;
    const timer = setTimeout(() => {
      tle.savePiAnalystProfile({
        suppressions: piAnalystProfile.suppressions || [],
        baselines: piAnalystProfile.baselines || [],
      }).catch(() => {});
    }, 150);
    return () => clearTimeout(timer);
  }, [tle, piAnalystProfile]);

  return { piAnalystProfile, setPiAnalystProfile };
}
