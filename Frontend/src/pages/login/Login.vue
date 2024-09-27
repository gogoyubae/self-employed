<template>
  <div
    class="mt-10 row g-0 justify-content-center gradient-bottom-right middle-indigo end-pink"
  >
    <div
      class="col-md-6 col-lg-5 col-xl-5 position-absolute start-0 vh-100 overflow-y-hidden d-none d-lg-flex flex-lg-column back-img"
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
    </div>
    <div
      class="col-12 col-md-12 col-lg-7 offset-lg-5 min-vh-100 d-flex flex-column justify-content-center position-relative bg-body border-start-lg shadow-soft-5"
      style="height: 100vh"
    >
      <div class="w-md-50 mx-auto px-10 px-md-0 py-10">
        <div class="mb-10">
          <a class="d-inline-block d-lg-none mb-10" href="/pages/dashboard.html"
            ><img
              src="../../img/logos/logo-dark.svg"
              class="h-rem-10"
              alt="..."
          /></a>
          <h1 class="ls-tight fw-bolder h3">맨트 뭘로 하지?</h1>
          <div class="mt-3 text-sm text-muted">
            <span>뭘로 할지 알려줘</span>
            <a href="/pages/login.html" class="fw-semibold">윤희</a>에몽
          </div>
        </div>
        <form>
          <div class="row g-5">
            <div class="col-sm-12">
              <label class="form-label">이메일</label>
              <input type="email" class="form-control" />
            </div>
            <div class="col-sm-12">
              <label class="form-label">비밀번호</label>
              <input type="password" class="form-control" />
            </div>
            <div class="col-sm-12">
              <a href="#" class="btn btn-dark w-100 mb-5">Login</a>
            </div>
          </div>
        </form>
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
  background-size: cover; /* 이미지가 div를 채우도록 설정 */
  background-position: center; /* 이미지를 중앙에 위치시킴 */
  height: 100vh; /* 왼쪽 이미지 div의 높이 설정 */
}
</style>
