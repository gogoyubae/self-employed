<template>
  <header>
    <div
      class="mx-2 mx-lg-auto position-relative z-2 px-lg-3 py-0 rounded-3 rounded-lg-pill bg-white he-visible"
      style="width: 90%"
    >
      <nav class="navbar navbar-expand-lg navbar-black p-0" id="navbar">
        <div class="container px-sm-0">
          <a class="navbar-brand d-inline-block w-lg-64" href="#"
            ><img
              src="../../assets/img/logos/logo-light.svg"
              class="h-rem-10"
              alt="..."
            /> </a
          ><button
            class="navbar-toggler"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#navbarCollapse"
            aria-controls="navbarCollapse"
            aria-expanded="false"
            aria-label="Toggle navigation"
          >
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="navbarCollapse">
            <ul class="navbar-nav gap-2 mx-lg-auto">
              <li class="nav-item">
                <a
                  class="fw-bold nav-link rounded-pill"
                  href="/report"
                  aria-current="page"
                  >시뮬레이션</a
                >
              </li>
              <li class="nav-item">
                <a class="fw-bold nav-link rounded-pill" href="/asset"
                  >가계관리</a
                >
              </li>
              <li class="nav-item">
                <a class="fw-bold nav-link rounded-pill" href="/community"
                  >커뮤니티</a
                >
              </li>
              <li class="nav-item">
                <router-link
                  class="fw-bold nav-link rounded-pill"
                  to="/infoPlaza/industry"
                  >정보광장</router-link
                >
              </li>
              <li class="nav-item">
                <a class="fw-bold nav-link rounded-pill" href="/mypage">
                  마이페이지
                </a>
              </li>
            </ul>
            <div
              class="navbar-nav align-items-lg-center justify-content-end gap-2 ms-lg-4 w-lg-64"
            >
              <a
                href="/pages/register.html"
                class="btn fw-bold btn-sm btn-warning bg-hover border-0 rounded-pill w-100 w-lg-auto mb-4 mb-lg-0"
                >회원가입</a
              >
              <a
                class="fw-bold nav-item nav-link rounded-pill d-none d-lg-block"
                href="/pages/login.html"
                >로그인</a
              >
            </div>
          </div>
        </div>
      </nav>
    </div>
  </header>
</template>

<script setup></script>
