<template>
  <div
    class="row g-0 justify-content-center gradient-bottom-right start-purple middle-indigo end-pink"
  >
    <div
      class="col-md-6 col-lg-5 col-xl-5 position-fixed start-0 vh-100 overflow-y-hidden d-none d-lg-flex flex-lg-column back-img"
    >
      <div class="p-12 py-xl-10 px-xl-20">
        <div class="mt-16">
          <h1 class="ls-tight fw-bolder display-6 text-white mb-5">
            Trade the world’s top assets and cryptos
          </h1>
          <p class="text-white text-opacity-75 pe-xl-24">
            Create beautiful websites that are supported by rock-solid design
            principles.
          </p>
        </div>
      </div>
      <div class="mt-auto ps-16 ps-xl-20">
        <img
          src="../../img/marketing/shot-1.png"
          class="img-fluid rounded-top-start-4"
          alt="..."
        />
      </div>
    </div>
    <div
      class="col-12 col-md-12 col-lg-7 offset-lg-5 min-vh-100 overflow-y-auto d-flex flex-column justify-content-center position-relative bg-body rounded-top-start-lg-4 border-start-lg shadow-soft-5"
    >
      <div class="w-md-50 mx-auto px-10 px-md-0 py-10">
        <div class="mb-10">
          <a class="d-inline-block d-lg-none mb-10" href="/pages/dashboard.html"
            ><img
              src="../../img/logos/logo-dark.svg"
              class="h-rem-10"
              alt="..."
          /></a>
          <h1 class="ls-tight fw-bolder h3">Get started. It&#39;s free</h1>
          <div class="mt-3 text-sm text-muted">
            <span>Already have an account?</span>
            <a href="/pages/login.html" class="fw-semibold">Sign in</a> to your
            account.
          </div>
        </div>
        <form>
          <div class="row g-5">
            <div class="col-sm-6">
              <label class="form-label">First name</label>
              <input type="text" class="form-control" />
            </div>
            <div class="col-sm-6">
              <label class="form-label">Last name</label>
              <input type="text" class="form-control" />
            </div>
            <div class="col-sm-12">
              <label class="form-label">Email address</label>
              <input type="email" class="form-control" />
            </div>
            <div class="col-sm-12">
              <label class="form-label">Password</label>
              <input type="password" class="form-control" />
            </div>
            <div class="col-sm-12">
              <label class="form-label">How did you hear about us?</label>
              <select class="form-select" aria-label="Default select example">
                <option value="1">Online search</option>
                <option value="2">Social media</option>
                <option value="3">Advertising</option>
              </select>
            </div>
            <div class="col-sm-12">
              <a href="#" class="btn btn-dark w-100">Sign up</a>
            </div>
          </div>
        </form>
        <div class="py-5 text-center">
          <span class="text-xs text-uppercase fw-semibold">or</span>
        </div>
        <div class="row g-2">
          <div class="col-sm-6">
            <a href="#" class="btn btn-neutral w-100"
              ><span class="icon icon-sm pe-2"
                ><img src="../../img/social/github.svg" alt="..." /> </span
              >Github</a
            >
          </div>
          <div class="col-sm-6">
            <a href="#" class="btn btn-neutral w-100"
              ><span class="icon icon-sm pe-2"
                ><img src="../../img/social/google.svg" alt="..." /> </span
              >Google</a
            >
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style>
.back-img {
  background-image: url('@/assets/img/register/register.jpg');
}
</style>
