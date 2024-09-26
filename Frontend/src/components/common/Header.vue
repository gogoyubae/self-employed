<template>
  <header>
    <div
      class="mx-2 mx-lg-auto position-relative z-2 px-lg-3 py-0 rounded-3 rounded-lg-pill bg-white"
      style="width: 80%"
    >
      <nav class="navbar navbar-expand-lg navbar-black p-0" id="navbar">
        <div class="container px-sm-0">
          <a class="navbar-brand d-inline-block" href="/"
            ><img
              src="@/assets/img/logos/Logo-hr-h-40.png"
              class=""
              alt="..."
            />
          </a>
          <button
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
              <li class="nav-item flex-item header-info-container">
                <a class="fw-bold nav-link rounded-pill" href="/simul">
                  시뮬레이션
                </a>
                <div class="header-info-dropdown">
                  <RouterLink to="/simul"><span>시작하기</span></RouterLink>
                  <RouterLink to="/simul/report"
                    ><span>결과보기</span></RouterLink
                  >
                </div>
              </li>

              <li class="nav-item">
                <a class="fw-bold nav-link rounded-pill" href="/asset"
                  >가계관리</a
                >
              </li>
              <li class="nav-item flex-item header-info-container">
                <a class="fw-bold nav-link rounded-pill" href="/community">
                  커뮤니티
                </a>
                <div class="header-info-dropdown">
                  <RouterLink to="/community"
                    ><span>음식/음료</span></RouterLink
                  >
                  <RouterLink to="/community"><span>유통</span></RouterLink>
                  <RouterLink to="/community"
                    ><span>패션/뷰티</span></RouterLink
                  >
                  <RouterLink to="/community"><span>의료</span></RouterLink>
                  <RouterLink to="/community"
                    ><span>여가/오락</span></RouterLink
                  >
                </div>
              </li>
              <li class="nav-item flex-item header-info-container">
                <a
                  class="fw-bold nav-link rounded-pill"
                  href="/infoPlaza/industry"
                >
                  정보광장
                </a>
                <div class="header-info-dropdown">
                  <RouterLink to="/infoPlaza/industry"
                    ><span>인기업종</span></RouterLink
                  >
                  <RouterLink to="/infoPlaza/floatpopular"
                    ><span>상권정보</span></RouterLink
                  >
                  <RouterLink to="/infoPlaza/education"
                    ><span>교육정보</span></RouterLink
                  >
                  <RouterLink to="/infoPlaza/personalLoan"
                    ><span>대출정보</span></RouterLink
                  >
                  <RouterLink to="/infoPlaza/news"
                    ><span>뉴스</span></RouterLink
                  >
                </div>
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

<style>
/* Dropdown styles for loan info */
.header-info-container {
  position: relative;
  flex: 1; /* Ensure it takes up available space */
}

.header-info-title {
  cursor: pointer;
  font-size: small;
  /* Add hover or click styles if needed */
}

.header-info-dropdown {
  display: block;
  position: absolute;
  top: 100%;
  left: 0;
  background-color: white;
  border-radius: 20px;
  box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-height: 0;
  overflow: hidden;
  opacity: 0;
  transition: max-height 0.3s ease, opacity 0.3s ease;
}

.header-info-container:hover .header-info-dropdown,
.header-info-container:focus-within .header-info-dropdown {
  display: block;
  max-height: 500px; /* Adjust as needed */
  opacity: 1;
}

.header-info-dropdown span {
  display: block;
  margin: 10px;
  font-size: small;
  cursor: pointer;
  text-align: center;
  color: black;
}

.header-info-dropdown span:hover {
  background-color: #f0f0f0;
  border-radius: 25px;
  font-size: small;
  font-weight: bold;
}

/* Ensure the link text doesn't wrap */
.nav-link {
  white-space: nowrap;
}
</style>
