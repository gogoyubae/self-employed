<template>
    <div>
        <InfoPlazaHeader />
        <div class="container">
            <div class="row">
                <CommercialHeader class="col-1"/>
                <div class="col-3">
                    <div>
                        <h4 class="mb-3">현위치</h4>
                        <div class="card border-primary-hover mb-5">
                            <div class="card-body d-flex gap-3">
                                <div class="">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 me-3"></i> <!-- Map icon from Bootstrap Icons -->
                                    <span class="d-inline text-muted mb-1">서울특별시 광진구 화양동</span>
                                </div>
                                <span class="stretched-link ms-auto text-muted text-primary-hover" data-bs-target="#cryptoModal" data-bs-toggle="modal" role="button">
                                <i class="bi bi-chevron-down"></i>
                                </span>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 class="mb-3">지역 선택</h4>
                        <div class="card border-primary-hover">
                            <div class="card-body d-flex gap-3">
                                <div class="">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 me-3"></i> <!-- Map icon from Bootstrap Icons -->
                                    <span class="d-inline text-muted mb-1">서울특별시 광진구 화양동</span>
                                </div>
                                <span class="stretched-link ms-auto text-muted text-primary-hover" data-bs-target="#cryptoModal" data-bs-toggle="modal" role="button">
                                <i class="bi bi-chevron-down"></i>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            <div class="col-8" ref="mapContainer" style="height: 70vh;"></div>

            <div class="modal fade" id="cryptoModal" tabindex="-1" aria-labelledby="cryptoModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content overflow-hidden">
                        <div class="modal-header pb-0 border-0">
                        <h1 class="modal-title h4" id="cryptoModalLabel">지역 선택</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body p-0">
                        <div class="px-6 py-5 border-bottom">
                            <input type="text" class="form-control" placeholder="검색어를 입력하세요" aria-label="Search">
                        </div>
                        <div class="p-2">
                            <div class="vstack">
                            <div class="position-relative d-flex gap-3 p-4 rounded bg-body-secondary-hover">
                                <div class="icon flex-none">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 mt-1 mx-3 me-3"></i>
                                </div>
                                <div class="d-flex flex-fill">
                                <div class="">
                                    <a href="#" class="stretched-link text-heading fw-bold">BTC</a>
                                    <span class="d-block text-muted text-sm">Bitcoin</span>
                                </div>
                                <div class="ms-auto fw-bold text-heading">
                                    23.8
                                </div>
                                </div>
                            </div>
                            <div class="position-relative d-flex gap-3 p-4 rounded bg-body-secondary-hover">
                                <div class="icon flex-none">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 mt-1 mx-3 me-3"></i>
                                </div>
                                <div class="d-flex flex-fill">
                                <div class="">
                                    <a href="#" class="stretched-link text-heading fw-bold">ETH</a>
                                    <span class="d-block text-muted text-sm">Ethereum</span>
                                </div>
                                <div class="ms-auto fw-bold text-heading">
                                    1.200,50
                                </div>
                                </div>
                            </div>
                            <div class="position-relative d-flex gap-3 p-4 rounded bg-body-secondary-hover">
                                <div class="icon flex-none">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 mt-1 mx-3 me-3"></i>
                                </div>
                                <div class="d-flex flex-fill">
                                <div class="">
                                    <a href="#" class="stretched-link text-heading fw-bold">ADA</a>
                                    <span class="d-block text-muted text-sm">Cardano</span>
                                </div>
                                <div class="ms-auto fw-bold text-heading">
                                    10.930,00
                                </div>
                                </div>
                            </div>
                            <div class="position-relative d-flex gap-3 p-4 rounded bg-body-secondary-hover">
                                <div class="icon flex-none">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 mt-1 mx-3 me-3"></i>
                                </div>
                                <div class="d-flex flex-fill">
                                <div class="">
                                    <a href="#" class="stretched-link text-heading fw-bold">BNB</a>
                                    <span class="d-block text-muted text-sm">Binance</span>
                                </div>
                                <div class="ms-auto fw-bold text-heading">
                                    200
                                </div>
                                </div>
                            </div>
                            <div class="position-relative d-flex gap-3 p-4 rounded bg-body-secondary-hover">
                                <div class="icon flex-none">
                                    <i class="bi bi-geo-alt w-rem-7 h-rem-7 mt-1 mx-3 me-3"></i>
                                </div>
                                <div class="d-flex flex-fill">
                                <div class="">
                                    <a href="#" class="stretched-link text-heading fw-bold">CHAIN</a>
                                    <span class="d-block text-muted text-sm">Linkchain</span>
                                </div>
                                <div class="ms-auto fw-bold text-heading">
                                    200
                                </div>
                                </div>
                            </div>
                            </div>
                        </div>
                            <div class="px-6 py-5 bg-body-secondary d-flex justify-content-center">
                                <button class="btn btn-sm btn-dark">
                                <i class="bi bi-gear me-2"></i>검색
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
</template>

<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
import CommercialHeader from '@/components/infoplaza/CommercialHeader.vue';
import { onMounted, ref } from 'vue';

const mapContainer = ref(null);


onMounted(() => {
    loadKakaoMap(mapContainer.value);
});

// Load Kakao Map
const loadKakaoMap = (container) => {
    const script = document.createElement('script');
    script.src = `https://dapi.kakao.com/v2/maps/sdk.js?appkey=09118387dc78b55b2c58f3876095c5d2&autoload=false`;
    document.head.appendChild(script);

    script.onload = () => {
        window.kakao.maps.load(() => {
            const options = {
                center: new window.kakao.maps.LatLng(33.450701, 126.570667), // Center coordinates
                level: 3, // Zoom level
                maxLevel: 5 // Maximum zoom level
            };

            const mapInstance = new window.kakao.maps.Map(container, options); // Create map instance
        });
    };
};

</script>
<style>
</style>