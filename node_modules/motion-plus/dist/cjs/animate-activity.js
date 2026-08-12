'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jsxRuntime = require('react/jsx-runtime');
var react$1 = require('motion/react');
var react = require('react');

function AnimateActivity({ mode: modeFromProps, layoutMode, children, }) {
    /**
     * This is the mode that we'll render.
     */
    const [mode, setMode] = react.useState(modeFromProps);
    /**
     * This is the goal state as defined by props.
     */
    const isPresent = modeFromProps === "visible";
    /**
     * Immediately switch to mode="visible" when the user
     * changes the mode prop.
     */
    if (isPresent && mode !== "visible") {
        setMode("visible");
        return null;
    }
    /**
     * Set mode to "hidden" only when the exit animation is complete.
     */
    const onExitComplete = () => setMode("hidden");
    react$1.invariant(Boolean(react.Activity), "Activity component not found - upgrade to React 19.2.0 or higher");
    return (jsxRuntime.jsx(react.Activity, { mode: mode, children: jsxRuntime.jsx(react$1.PresenceChild, { isPresent: isPresent, onExitComplete: !isPresent ? onExitComplete : undefined, presenceAffectsLayout: false, mode: layoutMode === "pop" ? "popLayout" : "sync", children: children }) }));
}

exports.AnimateActivity = AnimateActivity;
