'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jsxRuntime = require('react/jsx-runtime');
var React = require('react');
var motionDom = require('motion-dom');
var motionUtils = require('motion-utils');

const sharedProps = new Map();

function createViewAnimation(animationType, commitProps) {
    return ({ name }, types) => {
        const { transition, onAnimationStart, onAnimationComplete, ...props } = sharedProps.get(name) || commitProps;
        const layerAnimations = [];
        const generatedViewAnimations = motionDom.getViewAnimations();
        for (const viewAnimation of generatedViewAnimations) {
            if (viewAnimation.playState === "finished")
                continue;
            const { effect } = viewAnimation;
            if (!effect || !(effect instanceof KeyframeEffect))
                continue;
            const { pseudoElement } = effect;
            if (!pseudoElement)
                continue;
            const info = motionDom.getViewAnimationLayerInfo(pseudoElement);
            if (!info || info.layer !== name)
                continue;
            const transitionName = info.type === "group" ? "layout" : "";
            const { transition: typeTransition, ...values } = typeof props[animationType] === "function"
                ? props[animationType](types)
                : props[animationType] || {};
            if (Object.keys(values).length > 0) {
                // Custom values defined — cancel browser's default cross-fade
                // and replace with our own animations
                viewAnimation.cancel();
                layerAnimations.push(...createViewAnimations(name, animationType, values, transition, typeTransition));
            }
            else {
                // No custom values — keep browser animation but apply Motion timing
                let animationOptions = {
                    ...motionDom.getValueTransition(transition, transitionName),
                    ...motionDom.getValueTransition(typeTransition, transitionName),
                };
                animationOptions.duration = motionUtils.secondsToMilliseconds(animationOptions.duration ?? 0.3);
                animationOptions = motionDom.applyGeneratorOptions(animationOptions);
                const easing = motionDom.mapEasingToNativeEasing(animationOptions.ease, animationOptions.duration);
                effect.updateTiming({
                    delay: motionUtils.secondsToMilliseconds(animationOptions.delay ?? 0),
                    duration: animationOptions.duration,
                    easing,
                });
                layerAnimations.push(new motionDom.NativeAnimationWrapper(viewAnimation));
            }
        }
        const animation = new motionDom.GroupAnimation(layerAnimations);
        onAnimationStart?.(animation, animationType);
        if (onAnimationComplete) {
            animation.finished.then(() => {
                onAnimationComplete(animationType);
            });
        }
    };
}
function createViewAnimations(layerName, animationType, values, defaultTransition, transition) {
    const animations = [];
    for (let [name, keyframes] of Object.entries(values)) {
        const options = {
            ...motionDom.getValueTransition(defaultTransition, name),
            ...motionDom.getValueTransition(transition, name),
        };
        options.duration && (options.duration = motionUtils.secondsToMilliseconds(options.duration));
        options.delay && (options.delay = motionUtils.secondsToMilliseconds(options.delay));
        if (name === "opacity" && !Array.isArray(keyframes)) {
            const initialValue = animationType === "enter" ? 0 : 1;
            keyframes = [initialValue, keyframes];
        }
        const animation = new motionDom.NativeAnimation({
            ...options,
            element: document.documentElement,
            name,
            pseudoElement: `::view-transition-${animationType === "enter" ? "new" : "old"}(${layerName})`,
            keyframes,
        });
        animations.push(animation);
    }
    return animations;
}

let hasInsertedTransitionResetStyle = false;
function useResetViewTransitions() {
    React.useInsertionEffect(() => {
        if (hasInsertedTransitionResetStyle)
            return;
        hasInsertedTransitionResetStyle = true;
        const style = document.createElement("style");
        style.textContent = `
    ::view-transition-group(*), ::view-transition-old(*), ::view-transition-new(*) {
        animation-timing-function: linear !important;
    }
    `;
        document.head.appendChild(style);
    }, []);
}

const ViewTransition = React.ViewTransition;
function AnimateView({ children, ...props }) {
    useResetViewTransitions();
    const { name } = props;
    React.useInsertionEffect(() => {
        if (name) {
            sharedProps.set(name, props);
            return () => {
                sharedProps.delete(name);
            };
        }
    }, [name]);
    return (jsxRuntime.jsx(ViewTransition, { name: name, onEnter: createViewAnimation("enter", props), onExit: createViewAnimation("exit", props), onShare: createViewAnimation("share", props), onUpdate: createViewAnimation("update", props), children: children }));
}

exports.AnimateView = AnimateView;
