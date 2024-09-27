<template>
  <div>
    <InfoPlazaHeader />
    <div class="container mw-screen-xl">
      <PersonalLoanHeader class="mb-10" />
      <!-- Best 금리상품 title-->
      <div class="d-flex justify-content-center align-items-center">
        <div class="row">
          <div class="d-flex align-items-center mb-6">
            <img
              src="@/assets/img/infoplaza/thumbsUp.png"
              alt=""
              style="height: auto; max-height: 30px"
            />
            <h2 class="ms-2" style="font-weight: 700">BEST 금리 상품</h2>
          </div>
        </div>
      </div>
      <div class="card mb-10 p-4" style="background-color: #f6f4f9">
        <!-- Best 금리상품 내용-->
        <div class="row">
          <!-- 카드 1개 -->
          <div class="col-xl-3">
            <a href="#">
              <div class="card card-xl-stretch">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div class="d-flex flex-stack flex-wrap">
                      <span
                        class="fs-3 text-gray-500 pe-2"
                        style="font-weight: 500"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div class="d-flex flex-column flex-grow-1">
                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-end align-items-end ms-auto"
                            >
                              <p class="fs-6 text-gray-600 mb-1">금리</p>
                              <p class="h2 fw-bold mb-0 ms-2">3.83%</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </a>
          </div>
          <!-- 카드 1개 -->
          <div class="col-xl-3">
            <a href="#">
              <div class="card card-xl-stretch">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div class="d-flex flex-stack flex-wrap">
                      <span
                        class="fs-3 text-gray-500 pe-2"
                        style="font-weight: 500"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div class="d-flex flex-column flex-grow-1">
                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-end align-items-end ms-auto"
                            >
                              <p class="fs-6 text-gray-600 mb-1">금리</p>
                              <p class="h2 fw-bold mb-0 ms-2">3.83%</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </a>
          </div>
          <!-- 카드 1개 -->
          <div class="col-xl-3">
            <a href="#">
              <div class="card card-xl-stretch">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div class="d-flex flex-stack flex-wrap">
                      <span
                        class="fs-3 text-gray-500 pe-2"
                        style="font-weight: 500"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div class="d-flex flex-column flex-grow-1">
                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-end align-items-end ms-auto"
                            >
                              <p class="fs-6 text-gray-600 mb-1">금리</p>
                              <p class="h2 fw-bold mb-0 ms-2">3.83%</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </a>
          </div>
          <!-- 카드 1개 -->
          <div class="col-xl-3">
            <a href="#">
              <div class="card card-xl-stretch">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div class="d-flex flex-stack flex-wrap">
                      <span
                        class="fs-3 text-gray-500 pe-2"
                        style="font-weight: 500"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div class="d-flex flex-column flex-grow-1">
                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-end align-items-end ms-auto"
                            >
                              <p class="fs-6 text-gray-600 mb-1">금리</p>
                              <p class="h2 fw-bold mb-0 ms-2">3.83%</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </a>
          </div>
        </div>
      </div>

      <div class="row mb-4">
        <div class="col-xl-2"></div>
        <!-- 필터링 및 검색 -->
        <div class="col-xl-10">
          <div class="col-xl-9 d-flex">
            <!-- 지역 검색(구) -->
            <div class="col-md-2">
              <select
                class="form-select round-corner"
                aria-label="Default select example"
              >
                <option selected disabled hidden>구분</option>
                <option value="1">직접대출</option>
                <option value="2">대리대출</option>
              </select>
            </div>
            <div class="col-md-8"></div>
            <!-- 검색창 -->
            <div class="col-md-6">
              <div class="h-100">
                <form class="h-100 form-group">
                  <div class="h-100 input-group input-group-sm">
                    <input
                      type="text"
                      class="rounded form-control ms-1"
                      placeholder="검색어를 입력해 주세요."
                    />
                    <span class="ms-1 rounded input-group-text">
                      <i class="bi bi-search"></i>
                    </span>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="row">
        <!-- 좌측 정책자금 / 국민은행 구분 탭 -->
        <div class="col-xl-2">
          <div class="list-group list-group-flush gap-2">
            <div
              class="list-group-item gap-3 text-center p-3 bg-body-secondary-hover"
            >
              <div class="icon flex-none">
                <div class="icon flex-none">
                  <img
                    src="@/assets/img/infoplaza/popular.png"
                    class="w-rem-8 h-rem-8"
                    alt="..."
                  />
                </div>
              </div>
              <div class="align-items-center flex-fill">
                <div>
                  <a
                    href="#"
                    class="stretched-link text-heading text-sm fw-bold"
                    >개인신용대출</a
                  >
                </div>
              </div>
            </div>
            <div
              class="list-group-item gap-3 text-center p-3 bg-body-secondary-hover"
            >
              <div class="icon flex-none">
                <img
                  src="@/assets/img/infoplaza/storeinfo.png"
                  class="w-rem-8 h-rem-8"
                  alt="..."
                />
              </div>
              <div class="align-items-center flex-fill">
                <div>
                  <a
                    href="#"
                    class="stretched-link text-heading text-sm fw-bold"
                    >전세자금대출</a
                  >
                </div>
              </div>
            </div>
            <div
              class="list-group-item gap-3 p-3 text-center bg-body-secondary-hover"
            >
              <div class="icon flex-none">
                <img
                  src="@/assets/img/infoplaza/add_business.png"
                  class="w-rem-8 h-rem-8"
                  alt="..."
                />
              </div>
              <div class="align-items-center flex-fill">
                <div>
                  <a
                    href="#"
                    class="stretched-link text-heading text-sm fw-bold"
                    >주택담보대출</a
                  >
                </div>
              </div>
            </div>
          </div>
        </div>
        <!-- 대출 상품 내용 -->
        <div class="col-xl-10">
          <!-- 대출 상품 카드 내용 -->
          <div class="row">
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_KB.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_토스.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_신한.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_우리.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_토스.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_토스.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_토스.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_토스.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
            <!-- 카드 1개 -->
            <div class="col-xl-4">
              <div class="card card-xl-stretch mb-5 mb-xl-8">
                <div class="card-body pt-5">
                  <div
                    id="kt_stats_widget_8_carousel"
                    class="carousel carousel-custom carousel-stretch slide"
                    data-bs-ride="carousel"
                    data-bs-interval="8000"
                  >
                    <div style="width: 25%">
                      <img
                        src="@/assets/img/banklogo/금융아이콘_PNG_토스.png"
                        alt=""
                      />
                    </div>
                    <div class="d-flex flex-stack flex-wrap">
                      <span class="fs-3 text-gray-500 fw-bolder pe-2 pt-4"
                        >혁신성장촉진자금</span
                      >
                    </div>
                    <div class="carousel-inner pt-6">
                      <div class="carousel-item active">
                        <div class="carousel-wrapper">
                          <div
                            class="d-flex flex-column justify-content-between flex-grow-1"
                          >
                            <!-- 첫 번째 행: 신청기간 마감 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">신청기간</p>
                              <p class="fs-5 fw-bolder">마감됨</p>
                            </div>

                            <!-- 두 번째 행: 구분 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5">구분</p>
                              <p class="fs-5 fw-bolder">
                                성장기반자금/직접대출
                              </p>
                            </div>

                            <!-- 세 번째 행: 금리 -->
                            <div
                              class="d-flex justify-content-between align-items-center"
                            >
                              <p class="fs-5 0">금리</p>
                              <p class="fs-5 fw-bolder">3.83%</p>
                            </div>
                          </div>

                          <!-- Info (상세 보기 버튼) -->
                          <div class="d-flex justify-content-end pt-4">
                            <a
                              href="#"
                              class="btn btn-light btn-sm btn-color-muted fs-7 fw-bolder px-5"
                              >상세 보기</a
                            >
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <!-- 카드 1개끝 -->
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
import PersonalLoanHeader from '@/components/infoplaza/PersonalLoanHeader.vue';
</script>

<style></style>
