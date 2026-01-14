//! C ABI math functions using pure Rust libm.
//! Replaces openlibm for pure Rust builds.

use core::ffi::c_double;
use core::ffi::c_float;
use core::ffi::c_int;

// Basic trigonometric functions
#[unsafe(no_mangle)]
pub extern "C" fn sin(x: c_double) -> c_double {
    libm::sin(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cos(x: c_double) -> c_double {
    libm::cos(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tan(x: c_double) -> c_double {
    libm::tan(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn sinf(x: c_float) -> c_float {
    libm::sinf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cosf(x: c_float) -> c_float {
    libm::cosf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tanf(x: c_float) -> c_float {
    libm::tanf(x)
}

// Inverse trigonometric functions
#[unsafe(no_mangle)]
pub extern "C" fn asin(x: c_double) -> c_double {
    libm::asin(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn acos(x: c_double) -> c_double {
    libm::acos(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn atan(x: c_double) -> c_double {
    libm::atan(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn atan2(y: c_double, x: c_double) -> c_double {
    libm::atan2(y, x)
}

#[unsafe(no_mangle)]
pub extern "C" fn asinf(x: c_float) -> c_float {
    libm::asinf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn acosf(x: c_float) -> c_float {
    libm::acosf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn atanf(x: c_float) -> c_float {
    libm::atanf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn atan2f(y: c_float, x: c_float) -> c_float {
    libm::atan2f(y, x)
}

// Hyperbolic functions
#[unsafe(no_mangle)]
pub extern "C" fn sinh(x: c_double) -> c_double {
    libm::sinh(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cosh(x: c_double) -> c_double {
    libm::cosh(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tanh(x: c_double) -> c_double {
    libm::tanh(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn sinhf(x: c_float) -> c_float {
    libm::sinhf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn coshf(x: c_float) -> c_float {
    libm::coshf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tanhf(x: c_float) -> c_float {
    libm::tanhf(x)
}

// Inverse hyperbolic functions
#[unsafe(no_mangle)]
pub extern "C" fn asinh(x: c_double) -> c_double {
    libm::asinh(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn acosh(x: c_double) -> c_double {
    libm::acosh(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn atanh(x: c_double) -> c_double {
    libm::atanh(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn asinhf(x: c_float) -> c_float {
    libm::asinhf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn acoshf(x: c_float) -> c_float {
    libm::acoshf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn atanhf(x: c_float) -> c_float {
    libm::atanhf(x)
}

// Exponential and logarithmic functions
#[unsafe(no_mangle)]
pub extern "C" fn exp(x: c_double) -> c_double {
    libm::exp(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn exp2(x: c_double) -> c_double {
    libm::exp2(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn expm1(x: c_double) -> c_double {
    libm::expm1(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn expf(x: c_float) -> c_float {
    libm::expf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn exp2f(x: c_float) -> c_float {
    libm::exp2f(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn expm1f(x: c_float) -> c_float {
    libm::expm1f(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log(x: c_double) -> c_double {
    libm::log(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log2(x: c_double) -> c_double {
    libm::log2(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log10(x: c_double) -> c_double {
    libm::log10(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log1p(x: c_double) -> c_double {
    libm::log1p(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn logf(x: c_float) -> c_float {
    libm::logf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log2f(x: c_float) -> c_float {
    libm::log2f(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log10f(x: c_float) -> c_float {
    libm::log10f(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn log1pf(x: c_float) -> c_float {
    libm::log1pf(x)
}

// Power functions
#[unsafe(no_mangle)]
pub extern "C" fn pow(x: c_double, y: c_double) -> c_double {
    libm::pow(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn sqrt(x: c_double) -> c_double {
    libm::sqrt(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cbrt(x: c_double) -> c_double {
    libm::cbrt(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn hypot(x: c_double, y: c_double) -> c_double {
    libm::hypot(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn powf(x: c_float, y: c_float) -> c_float {
    libm::powf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn sqrtf(x: c_float) -> c_float {
    libm::sqrtf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn cbrtf(x: c_float) -> c_float {
    libm::cbrtf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn hypotf(x: c_float, y: c_float) -> c_float {
    libm::hypotf(x, y)
}

// Rounding and remainder functions
#[unsafe(no_mangle)]
pub extern "C" fn ceil(x: c_double) -> c_double {
    libm::ceil(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn floor(x: c_double) -> c_double {
    libm::floor(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn trunc(x: c_double) -> c_double {
    libm::trunc(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn round(x: c_double) -> c_double {
    libm::round(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn rint(x: c_double) -> c_double {
    libm::rint(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn nearbyint(x: c_double) -> c_double {
    libm::rint(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn ceilf(x: c_float) -> c_float {
    libm::ceilf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn floorf(x: c_float) -> c_float {
    libm::floorf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn truncf(x: c_float) -> c_float {
    libm::truncf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn roundf(x: c_float) -> c_float {
    libm::roundf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn rintf(x: c_float) -> c_float {
    libm::rintf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn nearbyintf(x: c_float) -> c_float {
    libm::rintf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmod(x: c_double, y: c_double) -> c_double {
    libm::fmod(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmodf(x: c_float, y: c_float) -> c_float {
    libm::fmodf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn remainder(x: c_double, y: c_double) -> c_double {
    libm::remainder(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn remainderf(x: c_float, y: c_float) -> c_float {
    libm::remainderf(x, y)
}

// Floating-point manipulation functions
#[unsafe(no_mangle)]
pub extern "C" fn fabs(x: c_double) -> c_double {
    libm::fabs(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn fabsf(x: c_float) -> c_float {
    libm::fabsf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn copysign(x: c_double, y: c_double) -> c_double {
    libm::copysign(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn copysignf(x: c_float, y: c_float) -> c_float {
    libm::copysignf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fdim(x: c_double, y: c_double) -> c_double {
    libm::fdim(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fdimf(x: c_float, y: c_float) -> c_float {
    libm::fdimf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmax(x: c_double, y: c_double) -> c_double {
    libm::fmax(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmin(x: c_double, y: c_double) -> c_double {
    libm::fmin(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaxf(x: c_float, y: c_float) -> c_float {
    libm::fmaxf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fminf(x: c_float, y: c_float) -> c_float {
    libm::fminf(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn fma(x: c_double, y: c_double, z: c_double) -> c_double {
    libm::fma(x, y, z)
}

#[unsafe(no_mangle)]
pub extern "C" fn fmaf(x: c_float, y: c_float, z: c_float) -> c_float {
    libm::fmaf(x, y, z)
}

// Integer-returning functions
#[unsafe(no_mangle)]
pub extern "C" fn lround(x: c_double) -> c_int {
    libm::round(x) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn lroundf(x: c_float) -> c_int {
    libm::roundf(x) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn lrint(x: c_double) -> c_int {
    libm::rint(x) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn lrintf(x: c_float) -> c_int {
    libm::rintf(x) as c_int
}

// Bessel functions
#[unsafe(no_mangle)]
pub extern "C" fn j0(x: c_double) -> c_double {
    libm::j0(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn j1(x: c_double) -> c_double {
    libm::j1(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn jn(n: c_int, x: c_double) -> c_double {
    libm::jn(n, x)
}

#[unsafe(no_mangle)]
pub extern "C" fn y0(x: c_double) -> c_double {
    libm::y0(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn y1(x: c_double) -> c_double {
    libm::y1(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn yn(n: c_int, x: c_double) -> c_double {
    libm::yn(n, x)
}

// Error functions
#[unsafe(no_mangle)]
pub extern "C" fn erf(x: c_double) -> c_double {
    libm::erf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn erfc(x: c_double) -> c_double {
    libm::erfc(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn erff(x: c_float) -> c_float {
    libm::erff(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn erfcf(x: c_float) -> c_float {
    libm::erfcf(x)
}

// Gamma functions
#[unsafe(no_mangle)]
pub extern "C" fn lgamma(x: c_double) -> c_double {
    libm::lgamma(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tgamma(x: c_double) -> c_double {
    libm::tgamma(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn lgammaf(x: c_float) -> c_float {
    libm::lgammaf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn tgammaf(x: c_float) -> c_float {
    libm::tgammaf(x)
}

// Decomposition functions
#[unsafe(no_mangle)]
pub extern "C" fn frexp(x: c_double, exp: *mut c_int) -> c_double {
    let (frac, e) = libm::frexp(x);
    if !exp.is_null() {
        unsafe { *exp = e };
    }
    frac
}

#[unsafe(no_mangle)]
pub extern "C" fn frexpf(x: c_float, exp: *mut c_int) -> c_float {
    let (frac, e) = libm::frexpf(x);
    if !exp.is_null() {
        unsafe { *exp = e };
    }
    frac
}

#[unsafe(no_mangle)]
pub extern "C" fn ldexp(x: c_double, exp: c_int) -> c_double {
    libm::ldexp(x, exp)
}

#[unsafe(no_mangle)]
pub extern "C" fn ldexpf(x: c_float, exp: c_int) -> c_float {
    libm::ldexpf(x, exp)
}

#[unsafe(no_mangle)]
pub extern "C" fn modf(x: c_double, iptr: *mut c_double) -> c_double {
    let (frac, int) = libm::modf(x);
    if !iptr.is_null() {
        unsafe { *iptr = int };
    }
    frac
}

#[unsafe(no_mangle)]
pub extern "C" fn modff(x: c_float, iptr: *mut c_float) -> c_float {
    let (frac, int) = libm::modff(x);
    if !iptr.is_null() {
        unsafe { *iptr = int };
    }
    frac
}

#[unsafe(no_mangle)]
pub extern "C" fn ilogb(x: c_double) -> c_int {
    libm::ilogb(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn ilogbf(x: c_float) -> c_int {
    libm::ilogbf(x)
}

#[unsafe(no_mangle)]
pub extern "C" fn logb(x: c_double) -> c_double {
    // logb returns the exponent as a floating point value
    libm::ilogb(x) as c_double
}

#[unsafe(no_mangle)]
pub extern "C" fn logbf(x: c_float) -> c_float {
    // logb returns the exponent as a floating point value
    libm::ilogbf(x) as c_float
}

#[unsafe(no_mangle)]
pub extern "C" fn scalbn(x: c_double, n: c_int) -> c_double {
    libm::scalbn(x, n)
}

#[unsafe(no_mangle)]
pub extern "C" fn scalbnf(x: c_float, n: c_int) -> c_float {
    libm::scalbnf(x, n)
}

// nextafter functions
#[unsafe(no_mangle)]
pub extern "C" fn nextafter(x: c_double, y: c_double) -> c_double {
    libm::nextafter(x, y)
}

#[unsafe(no_mangle)]
pub extern "C" fn nextafterf(x: c_float, y: c_float) -> c_float {
    libm::nextafterf(x, y)
}

// remquo
#[unsafe(no_mangle)]
pub extern "C" fn remquo(x: c_double, y: c_double, quo: *mut c_int) -> c_double {
    let (rem, q) = libm::remquo(x, y);
    if !quo.is_null() {
        unsafe { *quo = q };
    }
    rem
}

#[unsafe(no_mangle)]
pub extern "C" fn remquof(x: c_float, y: c_float, quo: *mut c_int) -> c_float {
    let (rem, q) = libm::remquof(x, y);
    if !quo.is_null() {
        unsafe { *quo = q };
    }
    rem
}

// Classification functions
#[unsafe(no_mangle)]
pub extern "C" fn __fpclassify(x: c_double) -> c_int {
    if x.is_nan() {
        0 // FP_NAN
    } else if x.is_infinite() {
        1 // FP_INFINITE
    } else if x == 0.0 {
        2 // FP_ZERO
    } else if x.abs() < f64::MIN_POSITIVE {
        3 // FP_SUBNORMAL
    } else {
        4 // FP_NORMAL
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __fpclassifyf(x: c_float) -> c_int {
    if x.is_nan() {
        0 // FP_NAN
    } else if x.is_infinite() {
        1 // FP_INFINITE
    } else if x == 0.0 {
        2 // FP_ZERO
    } else if x.abs() < f32::MIN_POSITIVE {
        3 // FP_SUBNORMAL
    } else {
        4 // FP_NORMAL
    }
}
