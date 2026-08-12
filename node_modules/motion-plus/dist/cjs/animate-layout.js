'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var motion = require('motion');

function unstable_animateLayout(scopeOrUpdateDom, updateDomOrOptions, options) {
    const { scope, updateDom, defaultOptions } = motion.parseAnimateLayoutArgs(scopeOrUpdateDom, updateDomOrOptions, options);
    return new motion.LayoutAnimationBuilder(scope, updateDom, defaultOptions);
}

exports.unstable_animateLayout = unstable_animateLayout;
